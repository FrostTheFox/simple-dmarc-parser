# simple-dmarc-parser

simple-dmarc-parser is a basic Python script that reads the contents of an IMAP mailbox, seeks out DMARC RUA reports, downloads and parses them in aggregate to provide a basic summary of passes and failures.

## Function
The script will print any DMARC reports which had a failed result, so that you can review them. A summary will also be printed at the end by default, which shows how many reports had a pass/fail result from each provider, how many pass/fail results were found for each IP address, and how many pass/fail results were found for each domain.

The summary can be disabled if you only want to see failures. See the usage section for appropriate options.

## Installation
It's recommended that you install simple-dmarc-parser via pip so that it is available on the system:

`pip install simple-dmarc-parser`

## Usage
The script reads all unread messages in the mailbox provided, so you should only use this with a dedicated DMARC RUA address. simple-dmarc-parser does not process RUF reports.

simple-dmarc-parser accepts command line arguments, a config file, or it can prompt you for the IMAP server information.

Run `simple-dmarc-parser -h` for command line argument options. Or, just run `simple-dmarc-parser` and you will be prompted for the appropriate information. Your password will not be shown as you enter it.

A config file option is recommended for any sort of automation so that your credentials aren't potentially exposed in process lists. See the [example config file](simple-dmarc-parser.conf.example), place it in an appropriate location with sensible permissions, and run using `simple-dmarc-parser --config /path/to/config`

**Use the delete messages option with caution.** Messages deleted with this option **are not** put in a deleted folder. They are immediately removed from the IMAP server with no option for recovery. 

## Automatic Reports
You can use cron to run simple-dmarc-parser regularly and send you its output via email, or whatever source you can send to via the command line.

For example, the following cron entry running on your mail server will result in nightly DMARC summaries being sent by cron to the user running the job:

`0 0 * * * simple-dmarc-parser --config /path/to/config`

If you prefer a version that only notifies you on errors, you can use [this example script](dmarc_report.sh). Make sure you have `mailutils` installed, put the script in root's home directory, and install the following cronjob as root:

`0 0 * * * /root/dmarc_report.sh`

The script assumes your configuration is in /etc/simple-dmarc-parser.conf (make sure silent is true), and it will send its report to the root user on the local system. If you wish to send to send the reports off-system, change "root" to a full email address.