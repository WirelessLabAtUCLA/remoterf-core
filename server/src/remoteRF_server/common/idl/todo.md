* New Schema Manager (device manager parallel) that:
- Try Catch on the decorators
- Sever Device Manager (ie: nuke the guy, replace with schema based). Hosts will function the same (ie: don't touch the host shit)

- Loads all devices based on device_manifest.yml 
- Creates the server side 'stubs' for said devices (baed on the 'plugin' like system + fetching through .config/drivers/ ...)
- RPC routing through to schema manager + reservation checks, etc. (device) (ie: IDL:driver_func + API token)

* Proper Client side pipeline
- Reservation/login pipeline remains the same!
- Schema/Driver version is pulled upon device 'init' (ie: proper API token transaction -> punches the driver version back)
- Tries to locally cache said driver, if local version is outdated (or just not there) -> pull the device drive schema/data to the client -> client side builds << PIPELINE for this 
- This driver caching pipeline should activate BOTH on: successful reservation (and itll make sure the device drivers are properly populated, etc.), and upon first calling the system!
- Should generate a 'schema' stub on the client side library/.config so that when they write the code, syntax highlighting/intellisense works properly -> Schema should map one to one.

* Proper edge case delegation
- Server side function support / error handling -> piping back to the user (in a nice/digestable manner)
- Server side perhaps some sort of 'checker' for datatypes + debugging methods (ie: if you mess up the schema implementation)
^ like perhaps when the decorator is populating, it checks to see if the data in out is functional, etc? I am not sure 

- Implementing HackRF driver, testing integration with USRP, other big boi SDRs, NON-SDR equipment like cameras ...

* Integrating BACK with Host system (lmao ...) Big question of perhaps fundamental framework change? 
- Like each Host dynamical grabs from the server manifest their devices AND schemas, connects/runs said schemas, then connects up the 'device' pipes? (need to discuss/think about more!)

- Edge cases:
* User Group Edge cases (> 1 hour reservation times)
