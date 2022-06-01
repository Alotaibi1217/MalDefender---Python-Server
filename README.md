# Maldefender - Python server

Here on the server side, the PCAP file is input into an open-source network traffic feature extractor
tool, provided by the Canadian Institute called the CICFlowMeter. The tool extracts the needed features from the
PCAP and converts them into a CSV format. This is necessary to ensure that the ML model input has the same
format as the dataset it has dealt with previously.
Whenever the machine learning algorithm finishes classifying the network traffic, the result of classification
will be sent to the application through OneSignal. It’s a service that enables push notifications on Android. The
OneSignal will generate a unique ID for each client. Through the Rest API, the assigned unique ID in addition to
the PCAP file is sent from the application to the server through POST. However, the server will receive the PCAP
file through GET, from the webserver hosted on our server.

Moreover, the server will be able to handle multiple clients at the same time through threading. Whenever the
server gets a new connection request from any application on any Android device, it will handle the new request by
opening a new thread. This will allow multiple clients to access the application at the same time.
However, a maximum of 10 threads was limited on the server; this is due to two reasons, one is that the server
has limited resources that can’t handle more threads than that, and the other is that this would inhibit a Denial of
Service (DoS) attack, where continuous scanning requests are sent to the server in order to bring it down.
