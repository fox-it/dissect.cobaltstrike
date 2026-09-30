Beacon version identification
=============================

:py:mod:`dissect.cobaltstrike.version` can identify the version of a Cobalt Strike beacon based on the PE export timestamp. 
The following table lists the PE export timestamp and the corresponding Cobalt Strike version that have been collected and identified in the wild.

.. note::

   Starting from Cobalt Strike 4.11 (Mar 17, 2025) the PE export timestamp is no longer present in the beacon.
   For these and later versions the version is deduced from the maximum ``BeaconSetting`` enum value
   (:py:attr:`~dissect.cobaltstrike.beacon.BeaconConfig.max_setting_enum`) instead, using the
   :py:data:`~dissect.cobaltstrike.version.MAX_ENUM_TO_VERSION` mapping. This is less precise than the
   PE export timestamp based method.

.. csv-table:: Beacon version detection based on PE export timestamp
   :file: cobaltstrike-beacon-versions.csv
   :header-rows: 1
   :class: longtable

Use the ``beacon-dump`` command to identify the version of a Cobalt Strike beacon.
Use the ``-v`` flag to print extra information, including the PE export timestamp and the version of the beacon.

.. code-block::

   $ beacon-dump -v beacon.bin

   --------------------------------------------------
   pe_export_stamp = 1720799264, 0x66915020, Fri Jul 12 17:47:44 2024 - Cobalt Strike 4.10 (Jul 16, 2024)
   pe_compile_stamp = 1478837312, 0x58254440, Fri Nov 11 05:08:32 2016
   max_setting_enum = 78 - BeaconSetting.SETTING_BEACON_GATE
   beacon_version = Cobalt Strike 4.10 (Jul 16, 2024)

If the version is unknown, the ``beacon-dump`` command will print the PE export timestamp and the version ``Unknown``.
A GitHub issue is welcome to add the PE export timestamp and the corresponding Cobalt Strike version to the table.

For beacons without a PE export timestamp (Cobalt Strike 4.11 and later), the version is deduced from the
maximum ``BeaconSetting`` enum value instead:

.. code-block::

   $ beacon-dump -v beacon.bin

   --------------------------------------------------
   pe_export_stamp = None Cobalt Strike 4.11 (Mar 17, 2025) beacon.bin
   max_setting_enum = 87 - BeaconSetting.SETTING_DNS_DOH_HEADERS
   beacon_version = Cobalt Strike 4.11 (Mar 17, 2025)