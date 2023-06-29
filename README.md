# Generic EDR Add-On for Splunk
こんにちわ！

### Some notes
* Built without referencing a running Splunk or EDR platform.
* Only tested ad-hoc requests with simple FastAPI listener (see other folder.)
* Learned about some new/changed libraries 
  * solnlib is now open source!
  * dataclasses are great, JSONWizard is a lifesaver.

## Components
* `genedr`: Python library for Generic EDR
* `TA-generic_edr`: Implements `genedr` to query and index alerts in Splunk
* Various libs as seen in `pyproject.toml`

## The Future
Assuming the TA is in working order and pulling in alerts fine...
* TESTS
* Packaging build/release (ksconf, slim)