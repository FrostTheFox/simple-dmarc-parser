import os
import shutil
import xmltodict
import gzip
import sys
import json
import argparse
import tempfile
from imap_tools import MailBox, AND
from time import localtime

parser = argparse.ArgumentParser(description='A tool that processes DMARC reports from a mailbox and gives a basic summary.')
parser.add_argument('--server', help='IMAP Server IP/FQDN', required=False)
parser.add_argument('--username', help='IMAP Username', required=False)
parser.add_argument('--password', help='IMAP Password', required=False)
parser.add_argument('--config', help='Config file to use', required=False)
parser.add_argument('--delete', help='Delete report messages after processing. THIS CANNOT BE UNDONE.', action='store_true')
parser.add_argument('--silent', help='Silences non-error output.', action='store_true')
parser.add_argument('--asjson', help='Prints non-error output in json format', action='store_true')


def process_record(record, sources, domains):
    """
    Function that processes individual records within a DMARC report file.

    Required arguments:
        record: A dictionary version of the "record" tree from the DMARC report.
        sources: A dictionary containing all source IP addresses found so far.
        domains: A dictionary containing all source domains found so far.

    Returns:
        ok: Boolean which signals whether a DMARC failure occurred.
        sources: Updated version of the argument which contains the processed IP address.
        domains: Updated version of the argument which contains the processed domain.
    """
    # Fetch needed info from the report data.
    source_ip = record['row']['source_ip']
    source_domain = record['identifiers']['header_from']
    count = int(record['row']['count'])
    dkim = record['row']['policy_evaluated']['dkim']
    spf = record['row']['policy_evaluated']['spf']

    # DKIM fail and SPF fail required to fail DMARC
    if dkim == 'fail' and spf == 'fail':
        ok = False
    else:
        ok = True

    # Set up the count dictionary if not existing for this IP
    if source_ip not in sources:
        sources[source_ip] = {'count': {'passed': 0, 'failed': 0}}

    # Set up the count dictionary if not existing for this domain
    if source_domain not in domains:
        domains[source_domain] = {'count': {'passed': 0, 'failed': 0}}

    # If all was well, increment the passed counter for the IP/domain.
    if ok:
        domains[source_domain]['count']['passed'] += count
        sources[source_ip]['count']['passed'] += count
    # Otherwise, increment failed counter for the IP/domain.
    if not ok:
        domains[source_domain]['count']['failed'] += count
        sources[source_ip]['count']['failed'] += count

    # Return our results.
    return ok, sources, domains


def main():
    """Command line entry function. Provides the main script flow."""
    args = parser.parse_args()

    # Prompt for credentials if nothing provided.
    if not len(sys.argv) > 1:
        from getpass import getpass
        server = input('IMAP Server IP/FQDN: ')
        username = input('IMAP Username: ')
        password = getpass(prompt='IMAP Password: ')
        if input('Delete messages? Press enter for default (n): ') == 'y':
            delete_messages = True
        else:
            delete_messages = False
        silent = False
        asjson = False
    # If config is provided, use that.
    elif args.config:
        with open(args.config, 'r') as f:
            config = json.loads(f.read())
            f.close()
        server = config['server']
        username = config['username']
        password = config['password']
        delete_messages = config['delete_messages']
        silent = config['silent']
        asjson = config['asjson']
    # Otherwise, use what is provided.
    else:
        server = args.server
        username = args.username
        password = args.password
        delete_messages = args.delete
        silent = args.silent
        asjson = args.asjson

    providers = {}
    sources = {}
    domains = {}
    uids = []
    json_response = {'generated':'%04d-%02d-%02d.%02d:%02d:%02d' % localtime()[:6]}
    

    directory = tempfile.mkdtemp()

    mailbox = MailBox(server).login(username, password)
    # Loop over unread messages.
    for msg in mailbox.fetch(AND(seen=False)):
        # Grab the message attachment.
        for att in msg.attachments:
            # Retain the original filename.
            filename = att.filename
            # Download the attachment.
            with open(os.path.join(directory, filename), 'wb') as f:
                f.write(att.payload)
                f.close()
            # Store UIDs for later deletion.
            uids.append(msg.uid)

    # If we didn't get anything from the IMAP server, exit.
    if not os.path.isdir(directory):
        if not silent:
            if not asjson:
                print('No reports found, exiting.')
            else:
                json_response.setdefault('messages',[]).append('No reports found, exiting.')
        sys.exit()

    for file in os.listdir(directory):
        filename = os.path.join(directory, file)
        # If it's a regular .gz archive
        if '.gz' in file and 'tar' not in file:
            # gzip doesn't provide a filename, so split out one
            outfile = filename.split('.gz')[0]
            # Open the archive file handler
            with gzip.open(filename, 'rb') as f_in:
                # Open the output file handler
                with open(outfile, 'wb') as f_out:
                    # Write to the output file from the archive file.
                    f_out.write(f_in.read())
        # All other archive types can be shutil unpacked.
        else:
            shutil.unpack_archive(filename, directory)

    # Refresh our file list.
    for file in os.listdir(directory):
        # Grab the actual XML files, not the compressed files.
        if '.xml' in file and '.gz' not in file:
            with open(os.path.join(directory, file), 'r', encoding='utf8') as f:
                content = f.read()

            # Convert XML to Dictionary. Data is within the 'feedback' header.
            data = xmltodict.parse(content)['feedback']
            # Fetch provider here since it's not in the record.
            provider = data['report_metadata']['org_name']

            # We only increment provider by 1, as this is just 1 report w/ potentially multiple records.
            if provider in providers:
                providers[provider] += 1
            else:
                providers[provider] = 1

            # Check for invalid reports that just contain report metadata.
            # These seem to come from "email security" scans? But they don't appear to be solicited, nor RFC compliant.
            if not 'record' in data:
                if not silent:
                    if not asjson:
                        print(f'Skipping report with no record: {file}')
                    else:
                        json_response.setdefault('messages',[]).append(f'Skipping report with no record: {file}')
                continue
            else:
                # Store the record(s) in a variable, so we can check if there's multiple.
                records = data['record']

            # List means multiple reports.
            if type(records) == list:
                for record in records:
                    ok, sources, domains = process_record(record, sources, domains)
            else:
                ok, sources, domains = process_record(records, sources, domains)

            # If the record processing reported a failure, let the user see it.
            if not ok:
                if not asjson:
                    print('\nFailed DMARC report, printing:')
                    print(data)
                else:
                    json_response.setdefault('messages',[]).append('Failed DMARC report, printing:')
                    json_response.setdefault('messages',[]).append(json.dumps(data))

    if not silent:
        # Output our summary.
        if not asjson:
            print('\nReports evaluated:')
        for provider in sorted(providers.keys()):
            if not asjson:
                print(f'{provider}: {providers[provider]}')
            else:
                json_response.setdefault('providers',{})[provider] = providers[provider]

        if not asjson:
            print('\nMessages per Source IP:')
        for source in sorted(sources.keys()):
            count = sources[source]['count']
            if not asjson:
                print(f"  {source}")
                print(f"    Passed: {count['passed']}")
                print(f"    Failed: {count['failed']}")
            else:
                json_response.setdefault('sources',{})[source] = {'passed':count['passed'],'failed':count['failed']}

        if not asjson:
            print('\nMessages per Source Domain:')
        for domain in sorted(domains.keys()):
            count = domains[domain]['count']
            if not asjson:
                print(f"  {domain}")
                print(f"    Passed: {count['passed']}")
                print(f"    Failed: {count['failed']}")
            else:
                json_response.setdefault('domains',{})[domain] = {'passed':count['passed'],'failed':count['failed']}
        if asjson:
            print(json.dumps(json_response,indent=2))

    # Clean up.
    shutil.rmtree(directory)
    if delete_messages:
        mailbox.delete(uids)

if __name__ == '__main__':
    main()
