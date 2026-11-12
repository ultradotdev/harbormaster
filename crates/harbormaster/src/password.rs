//! The UniFi Protect password while the daemon holds it.
//!
//! A detached daemon cannot read a locked Keychain, so the password is
//! found once (or handed over by `harbormaster unlock`) and then kept here,
//! in memory only, for every sign-in the bridge makes. It is never logged,
//! never written to disk and never part of a status snapshot, and the
//! memory is wiped when the last copy is dropped.

use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, Notify};
use zeroize::Zeroize;

/// A password. Printing it with `{:?}` shows a placeholder, and its bytes
/// are overwritten when it is dropped.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(text: String) -> Self {
        Self(text)
    }

    /// The password itself. Pass it straight to whatever needs it; do not
    /// copy it into a `String` that outlives the call.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[hidden]")
    }
}

/// How a sign-in with a handed-over password went.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    SignedIn { devices: usize },
    /// The console refused the password. It has been discarded and the
    /// daemon is waiting for another.
    Rejected(String),
    /// Signing in failed for another reason. The daemon keeps the password
    /// and keeps trying.
    Failed(String),
}

/// What the dashboard may know about the password: whether there is one,
/// never what it is.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct View {
    pub waiting: bool,
    /// Why the console is not connected, in plain words, if it is not.
    pub problem: Option<String>,
}

struct Inner {
    password: Option<Arc<Secret>>,
    /// How many devices the current session published, while signed in.
    signed_in: Option<usize>,
    problem: Option<String>,
    /// Whoever handed over the current password and is waiting to hear how
    /// the sign-in went.
    waiters: Vec<oneshot::Sender<Outcome>>,
}

pub struct Vault {
    inner: Mutex<Inner>,
    arrived: Notify,
}

impl Vault {
    pub fn new(initial: Option<Secret>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner { password: initial.map(Arc::new), signed_in: None, problem: None, waiters: Vec::new() }),
            arrived: Notify::new(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The owner hands a password over. The receiver hears how the next
    /// sign-in goes. While the bridge is signed in, the working password
    /// is kept and the new one is dropped unused.
    pub fn offer(&self, password: Secret) -> oneshot::Receiver<Outcome> {
        let (answer, outcome) = oneshot::channel();
        let mut inner = self.lock();
        if let Some(devices) = inner.signed_in {
            let _ = answer.send(Outcome::SignedIn { devices });
        } else if password.is_empty() {
            let _ = answer.send(Outcome::Rejected("the password was empty".into()));
        } else {
            inner.password = Some(Arc::new(password));
            inner.problem = None;
            inner.waiters.push(answer);
            self.arrived.notify_one();
        }
        outcome
    }

    /// The password, as soon as there is one.
    pub async fn password(&self) -> Arc<Secret> {
        loop {
            if let Some(password) = self.lock().password.clone() {
                return password;
            }
            self.arrived.notified().await;
        }
    }

    /// Resolves when a password is handed over, to cut a retry delay short.
    pub async fn arrival(&self) {
        self.arrived.notified().await;
    }

    pub fn signed_in(&self, devices: usize) {
        let mut inner = self.lock();
        inner.signed_in = Some(devices);
        inner.problem = None;
        for waiter in inner.waiters.drain(..) {
            let _ = waiter.send(Outcome::SignedIn { devices });
        }
    }

    /// The console refused `used`. It is discarded, unless the owner has
    /// handed over a newer one in the meantime, which gets its own try.
    pub fn rejected(&self, used: &Arc<Secret>, why: &str) {
        self.ended(used, why, true);
    }

    /// The session made with `used` failed or ended for a reason that is
    /// not the password's fault. The password is kept for the next try.
    pub fn failed(&self, used: &Arc<Secret>, why: &str) {
        self.ended(used, why, false);
    }

    fn ended(&self, used: &Arc<Secret>, why: &str, discard: bool) {
        let mut inner = self.lock();
        inner.signed_in = None;
        if !inner.password.as_ref().is_some_and(|current| Arc::ptr_eq(current, used)) {
            // A newer password is waiting for its own answer.
            return;
        }
        inner.problem = Some(why.to_owned());
        if discard {
            inner.password = None;
        }
        for waiter in inner.waiters.drain(..) {
            let _ = waiter.send(if discard { Outcome::Rejected(why.to_owned()) } else { Outcome::Failed(why.to_owned()) });
        }
    }

    pub fn view(&self) -> View {
        let inner = self.lock();
        View { waiting: inner.password.is_none(), problem: inner.problem.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(text: &str) -> Secret {
        Secret::new(text.to_owned())
    }

    #[test]
    fn a_secret_never_prints_itself() {
        let password = secret("correct horse");
        assert_eq!(format!("{password:?}"), "[hidden]");
        assert_eq!(format!("{:?}", Some(Arc::new(password.clone()))), "Some([hidden])");
        // It does travel over the owner's socket, as a bare string.
        assert_eq!(serde_json::to_string(&password).unwrap(), "\"correct horse\"");
    }

    #[tokio::test]
    async fn a_rejected_password_is_discarded_and_a_failed_one_is_kept() {
        let vault = Vault::new(None);
        assert!(vault.view().waiting);

        let answer = vault.offer(secret("wrong"));
        let used = vault.password().await;
        vault.rejected(&used, "the console rejected the username or password");
        assert_eq!(answer.await.unwrap(), Outcome::Rejected("the console rejected the username or password".into()));
        let view = vault.view();
        assert!(view.waiting && view.problem.as_deref().unwrap().contains("rejected"));

        let answer = vault.offer(secret("right"));
        let used = vault.password().await;
        vault.failed(&used, "could not reach the console");
        assert_eq!(answer.await.unwrap(), Outcome::Failed("could not reach the console".into()));
        assert!(!vault.view().waiting, "kept for the next try");
        assert_eq!(vault.password().await.expose(), "right");

        vault.signed_in(3);
        assert_eq!(vault.view(), View { waiting: false, problem: None });
        // Already signed in: the answer is immediate and the working password stays.
        assert_eq!(vault.offer(secret("another")).await.unwrap(), Outcome::SignedIn { devices: 3 });
        assert_eq!(vault.password().await.expose(), "right");
    }

    #[tokio::test]
    async fn a_newer_password_is_not_blamed_for_an_older_ones_failure() {
        let vault = Vault::new(Some(secret("old")));
        let used = vault.password().await;
        let mut answer = vault.offer(secret("new"));
        vault.rejected(&used, "rejected");
        assert!(answer.try_recv().is_err(), "the new password has not been tried yet");
        assert_eq!(vault.password().await.expose(), "new");
        assert_eq!(vault.offer(Secret::new(String::new())).await.unwrap(), Outcome::Rejected("the password was empty".into()));
    }

    #[tokio::test]
    async fn waiting_ends_the_moment_a_password_arrives() {
        let vault = Vault::new(None);
        let waiting = tokio::spawn({
            let vault = vault.clone();
            async move { vault.password().await.expose().to_owned() }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        let _answer = vault.offer(secret("here"));
        assert_eq!(waiting.await.unwrap(), "here");
    }
}
