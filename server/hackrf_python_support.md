# Adding HackRF Python Support to RemoteRF

This is the RemoteRF-specific note for adding HackRF support with the existing IDL driver model.

The accompanying schema file is [hackrf_schema.py](hackrf_schema.py). It is intended to be used as a driver plugin under:

```text
~/.config/remoterf/drivers/hackrf_schema.py
```

## Goal

Open the physical HackRF on the server by stable identifier only, then let the client configure frequency, sample rate, gains, bias tee, RX, and TX at runtime.

That means the server-side device manifest should stay minimal.

## Minimal Manifest

For HackRF, the manifest should usually contain only the serial number:

```yaml
devices:
  - device_id: 10
    device_type: hackrf
    name: HackRF One
    init:
      serial: "0000000000000000719031ac235bb14a"
```

If you really need it, the schema also supports `device_index`, but `serial` is the preferred identifier on a multi-device machine.

## Why Only `serial` Belongs in `init`

Settings like these should be controlled by the client or end user after connection:

- `center_freq`
- `sample_rate`
- `filter_bandwidth`
- `lna_gain`
- `vga_gain`
- `amplifier_on`
- `bias_tee_on`
- `txvga_gain`

Those are session-level operating parameters, not hardware identity.

Keeping them out of `init` avoids:

- stale defaults silently overriding user choices
- server startup side effects that change RF state before a client asks
- extra manifest churn for settings that are naturally runtime-controlled

## Chosen Python Wrapper

Use `pyhackrf2`.

Reasons:

- published on PyPI
- wraps the native `libhackrf` stack
- already exposes the operations RemoteRF needs first
- simple enough to model in the current schema framework

## Install Requirements

HackRF support needs both the native library/tools and the Python wrapper.

Example install:

```bash
sudo apt-get update
sudo apt-get install -y hackrf

python -m pip install --upgrade pip
python -m pip install pyhackrf2 numpy
```

Before testing Python, confirm the host sees the hardware:

```bash
hackrf_info
```

## What The Schema Exposes

The attached schema keeps startup minimal and exposes runtime control through IDL methods.

### Identity / discovery

- `call_enumerate`
- `call_get_serial_no`

### Runtime configuration

- `get_center_freq` / `set_center_freq`
- `get_sample_rate` / `set_sample_rate`
- `get_filter_bandwidth` / `set_filter_bandwidth`
- `get_lna_gain` / `set_lna_gain`
- `get_vga_gain` / `set_vga_gain`
- `get_amplifier_on` / `set_amplifier_on`
- `get_bias_tee_on` / `set_bias_tee_on`
- `get_txvga_gain` / `set_txvga_gain`
- `get_sample_count_limit` / `set_sample_count_limit`

### Data path

- `call_read_samples`
- `call_start_rx_buffered`
- `call_stop_rx`
- `call_get_buffer_iq`
- `call_clear_buffer`
- `call_load_tx_iq`
- `call_start_tx`
- `call_stop_tx`

## Why TX Uses Complex IQ Arrays

RemoteRF’s current protobuf mapping already handles NumPy arrays, including complex arrays, but not arbitrary byte blobs cleanly.

So the schema accepts TX payloads as complex IQ arrays and converts them to signed interleaved `int8` IQ bytes inside the driver before loading the HackRF TX buffer.

That keeps the RPC surface aligned with the current framework.

## Why RX Uses A Buffered Pattern

The existing generic RPC path is much better at request/response operations than callback streaming. For that reason, the schema uses a buffered RX model:

1. `call_start_rx_buffered(sample_count_limit=...)`
2. `call_stop_rx()`
3. `call_get_buffer_iq()`

That is a reasonable first integration without changing the transport model.

## Wrapper Safety Notes

The background research on `pyhackrf2` pointed out a few wrapper quirks:

- constructor naming around bias tee looks inconsistent
- close-state bookkeeping appears rough
- the `lna_gain` getter may be broken upstream
- sweep support looks less polished than RX/TX

Because of that, the schema uses a thin adapter object that caches runtime state locally and only relies on the wrapper for the actual hardware actions.

## Deployment Shape

The current repo already supports dynamic schema loading from `~/.config/remoterf/drivers`, so the lowest-friction path is:

1. put [hackrf_schema.py](hackrf_schema.py) in the drivers directory
2. add a `hackrf` device entry with only `serial`
3. restart the server

No hard-coded HackRF server shim is needed for this first pass.

## Bottom Line

For RemoteRF, the right model is:

- manifest identifies the physical device
- client configures the radio session

So yes, `serial` should be the important thing in `init`, and the attached schema is built around exactly that assumption.
