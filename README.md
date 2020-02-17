# nanoserver
A lightweight micropython implementation of an embedded LoRaWAN server. Combining the gateway forwarder from Pycom and a heavily modified floranet on a Lopy4 allows for a self-contained gateway. The Lopy4 is designed as a LoRaWAN endpoint but can run as a non-LoRaWAN-compliant single-channel gateway. May not want to use this in a production environment but nice for testing or battery operated gateway. This is very early test code in no way ready for actual use. Using a python implementation of aes-cmac from secworks slightly modified for micropython.

https://github.com/secworks/cmac
https://github.com/Fluent-networks/floranet
https://github.com/pycom/pycom-libraries/blob/master/examples/lorawan-nano-gateway/nanogateway.py

Need to do:
-fix hardcoded values for join requests, nonces, etc
-handle packet1, packet2 delays better
-test abp
-put keys in config or somewhere safer
-add mqtt or decrypted packets to a file
-add support for LoRaWAN v1.1
-clean up code 
-put MAC code in its own file
-lots more

Roughly working:
-OTAA join
-confirmed packets

To run add main.py, cmac.py, nanogateway.py, nanoserver.py, device.py, config.py onto Lopy4 running Pycom micropython(tested on ver 1.20.0.rc12 [v1.9.4-81167ed]). Appkey is in device.py for now. Need to add it somewhere safe. Looking for help testing and improving.
