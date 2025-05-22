## projects
- curl
- openssl
- tcpdump
- sqlite
- ffmpeg


## structure
- cveinfo: parsed cve information
- rawdata: cve info before any process
- releases: releae history of projects
- Diff: .diff for each CVE

## Todos
- Add patch version(latest vulnerable version +1)
- Add affected functions
- Filter CVEs without `References` or `last vulnerable version`
- Add .diff for each `valid` CVE manually