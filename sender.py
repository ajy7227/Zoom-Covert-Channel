import pyautogui
import time


if __name__ == "__main__":

    # Prompts for message and converts to string of binary
    msg = input("Enter your message: ")
    binary = ""
    for c in msg:
        binary += '{0:08b}'.format(ord(c))

    # Designates the start of the message with sending 5 bits of 1
    for i in range(0,4):
        pyautogui.hotkey("altleft", "y")
        i += 1

    # Uses Zoom global shortcuts to toggle raise/lower hand for 1
    # and mute/unmute for 0 every half second 
    for b in binary:
        if b == "1":
            pyautogui.hotkey("altleft", "y")
        if b == "0":
            pyautogui.hotkey("altleft", "a")
        time.sleep(.5)
    
