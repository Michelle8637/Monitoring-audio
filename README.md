# Monitoring-audio


# Usage
1) Lister les interfaces: `tshark -D`
2) Executer (VMnet8=3): `python .\realtime_tshark_sonification.py -i 3 --sensitivity medium --timestamp-format iso --debug`
3) Outputs update live: `normal_stream.txt` (sampled context) and `suspicious_stream.txt` (alerts only)
4) Stop: Ctrl+C
5) Pure Data reads each line as: `timestamp ip_src ip_dst intensity type`
