Initial codebase was forked from https://github.com/tgalal/python-axolotl but has since been heavily rewritten.

# Dependencies

 - [protobuf](https://pypi.org/project/protobuf/) (>=4.21.0)
 - [cryptography](https://pypi.org/project/cryptography/)

## Linux

```
pip install .
```

# Usage

This library handles only the crypto part of OMEMO, not the XMPP protocol part. This means you need to take care yourself of things like publishing/downloading bundles, publishing/subscribing to PEP deviceliste updates, sending and receiving messages.

## Building a session

A OMEMO client needs to implement the Store interface (omemo_dr.state.store.Store). This will manage loading and storing of identity, prekeys, signed prekeys, and session state.

Once this is implemented, building a session is fairly straightforward:

```python
storage = MyStorage()

config = OMEMOConfig(default_prekey_amount=100,
                     min_prekey_amount=80,
                     spk_archive_seconds=86400 * 15,
                     spk_cycle_seconds=86400,
                     unacknowledged_count=2000)

manager = OMEMOSessionManager(address, storage, config)

# Get your bundle for publishing
bundle = manager.get_bundle('eu.siacs.conversations.axolotl')
my_publish_method(bundle)

# Build a session with a downloaded bundle of a remote contact
bundle = my_receive_bundle_method()
manager.build_session(remote_address, bundle)

# Encrypt a message to a remote contact
message = manager.encrypt(remote_address, plaintext)
my_send_message_method(message)

# Descrypt a message
message = my_receive_message_method()
plaintext, fingerprint, trust = manager.decrypt(message, remote_address)
```

# Development

## Generating protobuf files

Download the protobuf-compiler > 3.19 and execute

```bash
$ protoc -I=src/omemo_dr/protobuf --python_out=src/omemo_dr/protocol omemo.proto whisper.proto
$ protoc -I=src/omemo_dr/protobuf --python_out=src/omemo_dr/state storage.proto
```
