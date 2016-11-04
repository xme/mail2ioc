#!/usr/bin/python
#
# TODO:
# - yaml configuration
# - multiple IMAP accounts
# - read all mailbox (not only unseen)
#
import imaplib
import email
import mailbox
import sys
import fileinput
import os
import glob
import re
import optparse
import yaml
import json
from time import gmtime, strftime

try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser

import Output

reload(sys)  
sys.setdefaultencoding('utf8')

class Parser(object):
    patterns = {}
    defang = {}

    def __init__(self, patterns_ini=None, dedup=True, output_format='csv', output_handler=None):
        basedir = os.path.abspath(os.path.dirname(__file__))
        if patterns_ini is None:
            patterns_ini = os.path.join(basedir, 'patterns.ini')
        self.load_patterns(patterns_ini)

        wldir = os.path.join(basedir, 'whitelists')
        self.whitelist = self.load_whitelists(wldir)
        self.dedup = dedup
        if output_handler:
            self.handler = output_handler
        else:
            self.handler = Output.getHandler(output_format)

#        self.ext_filter = '*.' + input_format
#       parser_format = 'parse_' + input_format
#       try:
#           self.parser_func = getattr(self, parser_format)
#       except AttributeError:
#           e = 'Selected parser format is not supported: %s' % (input_format)
#           raise NotImplementedError(e)

    def load_patterns(self, fpath):
        config = ConfigParser.ConfigParser()
        with open(fpath) as f:
            config.readfp(f)

        for ind_type in config.sections():
            try:
                ind_pattern = config.get(ind_type, 'pattern')
            except:
                continue

            if ind_pattern:
                ind_regex = re.compile(ind_pattern)
                self.patterns[ind_type] = ind_regex

            try:
                ind_defang = config.get(ind_type, 'defang')
            except:
                continue

            if ind_defang:
                self.defang[ind_type] = True

    def load_whitelists(self, fpath):
        whitelist = {}

        searchdir = os.path.join(fpath, "whitelist_*.ini")
        fpaths = glob.glob(searchdir)
        for fpath in fpaths:
            t = os.path.splitext(os.path.split(fpath)[1])[0].split('_',1)[1]
            patterns = [line.strip() for line in open(fpath)]
            whitelist[t]  = [re.compile(p) for p in patterns]

        return whitelist

    def is_whitelisted(self, ind_match, ind_type):
        try:
            for w in self.whitelist[ind_type]:
                if w.findall(ind_match):
                    return True
        except KeyError as e:
            pass
        return False

    def parse(self, mailbox, tags, data):
        try:
            if self.dedup:
                self.dedup_store = set()

            for ind_type, ind_regex in self.patterns.items():
                matches = ind_regex.findall(data)

                for ind_match in matches:
                    if isinstance(ind_match, tuple):
                        ind_match = ind_match[0]

                    if self.is_whitelisted(ind_match, ind_type):
                       continue

                    if ind_type in self.defang:
                        ind_match = re.sub(r'\[\.\]', '.', ind_match)
                        ind_match = re.sub(r'hxxp:', 'http', ind_match)

                    if self.dedup:
                        if (ind_type, ind_match) in self.dedup_store:
                            continue

                        self.dedup_store.add((ind_type, ind_match))

                    jsonData = {
                        'timestamp' : strftime("%Y-%m-%d %H:%M:%S", gmtime()),
                        'mailbox' : mailbox,
                        'tags' : tags,
                        'indicator' : ind_type,
                        'match' : ind_match
                    }
                    print(json.dumps(jsonData))
                    
#                    self.handler.print_match(1, ind_type, ind_match)

            # data = f.read()
            # self.handler.print_header(fpath)
            #self.parse_page(data, 1)
            # self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(data, e)

#   def parse(self, path):
#       try:
#           self.parser_func(path, 'stdin')
#           return
#       except (KeyboardInterrupt, SystemExit):
#           raise
#       except Exception as e:
#           self.handler.print_error(path, e)

def extract_body(p):
    ''' Extract body from the raw email '''
    if isinstance(p, str):
        return p
    else:
        return '\n'.join([extract_body(part.get_payload()) for part in p])

def parseConfigFile(configFile):
    global yamlConfig
    try:
        yamlConfig = yaml.load(file(configFile))
    except yaml.YAMLError, e:
        print "Error in configuration file:"
        if hasattr(e, 'problem_mark'):
            mark = e.problem_mark
            print "Error position: (%s, %s)" % (mark.line + 1, mark.column + 1)
            exit(1)
    
if __name__ == '__main__':
    parser = optparse.OptionParser("usage: %prog [options]")
    parser.add_option('-c','--config', dest="config",
                    help='load configuration from file', metavar='FILE')
    (options, args) = parser.parse_args()
    if not options.config:
        if os.path.isfile('/etc/mail2ioc.yaml'):
            options.config('/etc/mail2ioc.yaml')
        if os.path.isfile('mail2ioc.yaml'):
            options.config = 'mail2ioc.yaml'
    if not os.path.isfile(options.config):
        parser.error('Configuration file not found.')
        exit(1)

    parseConfigFile(options.config)

    for mailbox in yamlConfig['mailboxes']:
        print "--- DEBUG: Processing " + mailbox
        if yamlConfig['mailboxes'][mailbox]['ssl'] == True:
            imap = imaplib.IMAP4_SSL(yamlConfig['mailboxes'][mailbox]['server'])
        else:
            imap = imaplib.IMAP4(yamlConfig['mailboxes'][mailbox]['server'])
        try:
            (rc, capabilities) = imap.login(yamlConfig['mailboxes'][mailbox]['username'],
                                    yamlConfig['mailboxes'][mailbox]['password'])
        except:
            print sys.exc_info()[1]

        imap.list()
        if yamlConfig['mailboxes'][mailbox]['folder']:
            imap.select(yamlConfig['mailboxes'][mailbox]['folder'])
        else:
            imap.select('inbox')

        result, data = imap.uid('search', None, 'UNSEEN')
        i = len(data[0].split())

        for x in range(i):
            latest_email_uid = data[0].split()[x]
            result, email_data = imap.uid('fetch', latest_email_uid, '(RFC822)')
            # result, email_data = conn.store(num,'-FLAGS','\\Seen') 
            # this might work to set flag to seen, if it doesn't already
            raw_email = email_data[0][1]
            raw_email_string = raw_email.decode('utf-8')
            email_message = email.message_from_string(raw_email_string)
            
            
            #email_from = str(email.header.make_header(email.header.decode_header(email_message['From']))).decode('utf-8')
            #email_to = str(email.header.make_header(email.header.decode_header(email_message['To']))).decode('utf-8')
            #subject = str(email.header.make_header(email.header.decode_header(email_message['Subject']))).decode('utf-8')
            
            # Header Details
            email_date    = email_message['Date']
            email_from    = email_message['From']
            email_to      = email_message['To']
            email_subject = email_message['Subject']

            # Extract mailing list tag from subject
            m = re.findall('\[(.*?)\]', email_subject)
            email_tags = list(set(m))
            
            print "+++ New email"
            print "+++ From: " + email_from
            print "+++ To: " + email_to
            print "+++ Subject: " + email_subject

            # Body details
            for part in email_message.walk():
                if part.get_content_type() == "text/plain":
                    email_body = part.get_payload(decode=True)
                    parser = Parser(None, True, 'csv')
                    parser.parse(mailbox, email_tags, email_body)
                else:
                    continue

            # Flag the message as 'Deleted' if requested by the configuration
            if yamlConfig['mailboxes'][mailbox]['delete'] == True:
                result = imap.uid('store', latest_email_uid, '+FLAGS', '(\\Deleted)')
                # print "DEBUG DELETE: " + result

        # Expunge messages flagged as 'deleted'            
        if yamlConfig['mailboxes'][mailbox]['delete'] == True:
            print '--- DEBUG: Expuging processed messages'
            result = imap.expunge()

