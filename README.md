# goshark
A Go based CLI application wrapper for tshark with a docker like CLI.

## GET URI(s)
fetches uri from http requests.
```aidl
$ ./goshark get uri http.pcap 
0 http://www.ethereal.com/download.html
1 http://pagead2.googlesyndication.com/pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&lmt=1082467020&format=468x60_as&output=html&url=http%3A%2F%2Fwww.ethereal.com%2Fdownload.html&color_bg=FFFFFF&color_text=333333&color_link=000000&color_url=666633&color_border=666633
```

## GET HOST(s)
fetches host name from http requests.
```
$ ./goshark get host pcaps/http.pcap 
0 www.ethereal.com
1 pagead2.googlesyndication.com
```
