# LE_FIND_PENDING_AUTHZ
Use Certbot Logs as a way of finding pending autz

# USAGE:

The Usage of the script should be pretty straight forward. 

The Script requires two paramaters which are defined at the top

**PATH:** the path to the log directory for Let's Encrypt - usually this is is /var/log/letsencrypt

**KEY FOLDER** - folder for Let's Encrypt Account Key. Usually /etc/letsencrypt/accounts/<random numbers and letters>

# TODO: 

maybe hard code the path - it seems to be consistent across most people who use the script
figure out account ID automatically from the log files so user does not have to enter the key folder (this should be able to be deduced from the log files)
add samples to run this as a post hook


