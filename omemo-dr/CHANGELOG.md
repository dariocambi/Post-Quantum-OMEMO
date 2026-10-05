omemo-dr 1.2.0 (25 Dec 2025)

  Improvements

  * SessionManager: Add convenience methods to modify group members

omemo-dr 1.1.0 (16 Nov 2025)

  Change

  * Allow encryption only to our own devices

omemo-dr 1.0.1 (08 Nov 2023)

  Improvements

  * PreKeyBundle: Allow 0 for signed pre key

omemo-dr 1.0.0 (26 May 2023)

  * No changes

omemo-dr 0.99.3 (20 May 2023)

  Improvements

  * Add more validation for bundle

  Change

  * Remove medium module
  * Make get_next_signed_pre_key_id() a helper method

omemo-dr 0.99.2 (13 May 2023)

  New

  * Add OMEMOSessionManager.set_trust()
  * Add OMEMOSessionManager.delete_session()
  * Add get_our_identity()
  * Add get_identity_infos()

  Improvements

  * Improve logging

  Change

  * Raise protobuf version to >= 4.21
  * Don’t allow direct storage access
  * Replace has_trusted_keys()
  * Rename OMEMOSession class
  * Replace "own" with "our"
  * Replace registration_id with device_id

omemo-dr 0.99.1 (03 May 2023)

  New

  * Add OMEMOSession
  * Add AES module

  Bug Fixes

  * Discover version correctly on install
  * Depend on setuptools 65+ for build
  * Pass integer for m_size arg
