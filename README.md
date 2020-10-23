# Zoom-Covert-Channel

### Sender
Make sure Zoom client for the has "Mute/Unmute My Audio" and "Raise\Lower Hand" keyboard shortcuts enabled globally.
Verify shortcut for Mute/Unmute is ALT+A and Raise\Lower Hand is ALT+Y

`python3 sender.py`

Enter message at the prompt.

### Receiver
Start wireshark capture right before sending begins. 

`python3 receiver.py test.pcapng`
