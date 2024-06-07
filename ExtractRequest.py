import pyshark

def extract_long_delayTime_requests(pcap_file, setTime):
    cap = pyshark.FileCapture(pcap_file, display_filter='http')

    request_times = {}

    for packet in cap:
        if 'HTTP' in packet:
            try:
                if hasattr(packet.http, 'request_full_uri'):
                    stream_index = packet.tcp.stream
                    request_time = float(packet.sniff_timestamp)
                    request_times[stream_index] = (packet, request_time)

                elif hasattr(packet.http, 'response_code'):
                    stream_index = packet.tcp.stream
                    response_time = float(packet.sniff_timestamp)

                    if stream_index in request_times:
                        request_packet, request_time = request_times[stream_index]
                        delayTime = response_time - request_time

                        if delayTime > setTime:
                            print(f"Request info: {request_packet.http.request_full_uri}")
                            print(f"delayTime: {delayTime} seconds")
                            print("")
            except AttributeError:
                continue

    cap.close()

pcap_file = 'input_file.pcap' # Input .pcap format file
setTime = 3  # Input delay time
extract_long_delayTime_requests(pcap_file, setTime)
