## PAM Bluetooth

This module is highly inspired by the [PAM module](https://github.com/nahil1/pam-bluetooth) written by nahil1.

This module gives the ability to authenticate if a given bluetooth device is connected to your computer.

### Requirements

To use this module you will need the bluetoothctl utils, you can install it on Arch Linux with this command:

    sudo pacman -S bluez-utils

### Installation
First modify the `MAC_ADDRESS` value in pam_bluetooth.c to match the MAC address of your device.

Then to install this module you should use the following commands:

    make
    sudo make install

Now that the module has been installed you will have to modify your PAM configuration.
Just add the following line to the appropriate config file in /etc/pam.d 

    auth sufficient pam_bluetooth.so
