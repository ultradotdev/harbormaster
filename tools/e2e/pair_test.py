"""Drive a running Harbormaster bridge with the aiohomekit controller."""
import asyncio, json, sys, tempfile, pathlib

from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf
from aiohomekit import Controller
from aiohomekit.characteristic_cache import CharacteristicCacheFile
from aiohomekit.zeroconf import ZeroconfServiceListener
from aiohomekit.exceptions import HomeKitException


async def main(state_file: str) -> int:
    state = json.load(open(state_file))
    device_id, pin = state["device_id"].lower(), state["setup_code"]
    work = pathlib.Path(tempfile.mkdtemp())
    zc = AsyncZeroconf()
    controller = Controller(async_zeroconf_instance=zc, char_cache=CharacteristicCacheFile(work / "charmap.json"))
    async with zc:
        browser = AsyncServiceBrowser(zc.zeroconf, ["_hap._tcp.local.", "_hap._udp.local."], listener=ZeroconfServiceListener())
        async with controller:
            discovery = await controller.async_find(device_id, timeout=15)
            print("1 discovered:", discovery.description.name, "paired =", discovery.paired)
            assert not discovery.paired

            wrong = "111-22-333" if pin != "111-22-333" else "111-22-334"
            try:
                finish = await discovery.async_start_pairing("bad")
                await finish(wrong)
                print("FAIL: wrong setup code was accepted")
                return 1
            except HomeKitException as e:
                print("2 wrong setup code rejected:", type(e).__name__)

            discovery = await controller.async_find(device_id, timeout=15)
            finish = await discovery.async_start_pairing("hm")
            pairing = await finish(pin)
            print("3 paired with correct setup code")

            accessories = await pairing.list_accessories_and_characteristics()
            target = None
            for a in accessories:
                for s in a["services"]:
                    for c in s["characteristics"]:
                        if c["type"].upper().lstrip("0").startswith("11") and len(c["type"]) <= 2 or c["type"].upper().startswith("00000011-"):
                            target = (a["aid"], c["iid"])
            print("4 accessories:", [a["aid"] for a in accessories], "temperature at", target)
            assert target and len(accessories) >= 2

            value = await pairing.get_characteristics([target])
            print("5 read:", value)
            assert "value" in value[target]

            bad = await pairing.get_characteristics([(1, 2), target])
            print("6 mixed read (write-only + ok):", bad)
            assert bad[(1, 2)].get("status") == -70405

            events = asyncio.Queue()
            pairing.dispatcher_connect(lambda data: events.put_nowait(data))
            await pairing.subscribe([target])
            event = await asyncio.wait_for(events.get(), timeout=20)
            print("7 event:", event)
            assert target in event

            result = await pairing.put_characteristics([(target[0], target[1], 5.0)])
            print("8 write to read-only:", result)
            assert result[target]["status"] == -70404

            listed = await pairing.list_pairings()
            print("9 pairings:", [(p["pairingId"][:8], p["controllerType"]) for p in listed])
            assert len(listed) == 1

            (pathlib.Path(state_file).parent / "controller.json").write_text(json.dumps({"hm": dict(pairing.pairing_data)}))
            print("10 controller pairing saved")
    print("PHASE 1 OK")
    return 0


async def resume(state_file: str) -> int:
    """After a bridge restart: reconnect with the saved pairing, then unpair."""
    work = pathlib.Path(tempfile.mkdtemp())
    zc = AsyncZeroconf()
    controller = Controller(async_zeroconf_instance=zc, char_cache=CharacteristicCacheFile(work / "charmap.json"))
    async with zc:
        browser = AsyncServiceBrowser(zc.zeroconf, ["_hap._tcp.local.", "_hap._udp.local."], listener=ZeroconfServiceListener())
        async with controller:
            controller.load_data(str(pathlib.Path(state_file).parent / "controller.json"))
            pairing = controller.aliases["hm"]
            accessories = await pairing.list_accessories_and_characteristics()
            print("11 reconnected after restart, accessories:", [a["aid"] for a in accessories])
            assert len(accessories) >= 2
            listed = await pairing.list_pairings()
            await pairing.remove_pairing(listed[0]["pairingId"])
            print("12 pairing removed")
    await asyncio.sleep(0.5)
    after = json.load(open(state_file))
    assert after["pairings"] == {}, after["pairings"]
    print("13 bridge state shows unpaired")
    print("PHASE 2 OK")
    return 0


sys.exit(asyncio.run((resume if sys.argv[1] == "resume" else main)(sys.argv[2])))
