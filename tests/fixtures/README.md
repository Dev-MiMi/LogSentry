# Test fixtures

`ssh_auth.log` contains fictional SSH events used to verify parsing, detection,
and CLI reports. Tests read it explicitly; the dashboard and collector never
load it automatically. Test records belong in temporary test stores, never in
the local collection database.
