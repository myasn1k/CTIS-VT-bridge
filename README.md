# CTIS-VT-bridge

Synchronize CTIS and VT yara rulesets, rules and matches for semi-automatic yara monitoring.

## Configuration

In `config_vol/`, please copy `config.sample.yaml` to `config.yaml`, and edit the following:

* CTIS url
* CTIS user
* CTIS password
* The name of the source used: any yara matching this source will be pushed to VT
* The name of the type used: type name used for yara rulesets
* The name of the type used: type name used for yara rules
* VT api key

## Usage

1. Build the container: `docker-compose build app`
2. Add crontab
	- Example crontab entry: `*/30 * * * * cd /PATH/TO/CTIS-VT-bridge && ./run.sh`
