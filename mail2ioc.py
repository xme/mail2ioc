#!/usr/bin/python
#
# Original code from ioc_parser (https://github.com/armbues/ioc_parser)
#

import fileinput
import os
import sys
import email
import glob
import re

try:
	import configparser as ConfigParser
except ImportError:
	import ConfigParser

import Output

class Parser(object):
	patterns = {}
	defang = {}

	def __init__(self, patterns_ini=None, input_format='pdf', dedup=False, library='pdfminer', output_format='csv', output_handler=None):
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

		self.ext_filter = '*.' + input_format
		parser_format = 'parse_' + input_format
		try:
			self.parser_func = getattr(self, parser_format)
		except AttributeError:
			e = 'Selected parser format is not supported: %s' % (input_format)
			raise NotImplementedError(e)

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

	def parse_page(self, fpath, data, page_num):
		for ind_type, ind_regex in self.patterns.items():
			matches = ind_regex.findall(data)

			for ind_match in matches:
				if isinstance(ind_match, tuple):
					ind_match = ind_match[0]

				if self.is_whitelisted(ind_match, ind_type):
					continue

				if ind_type in self.defang:
					ind_match = re.sub(r'\[\.\]', '.', ind_match)

				if self.dedup:
					if (ind_type, ind_match) in self.dedup_store:
						continue

					self.dedup_store.add((ind_type, ind_match))

				self.handler.print_match(fpath, page_num, ind_type, ind_match)

	def parse_txt(self, data, fpath):
		try:
			if self.dedup:
				self.dedup_store = set()

			# data = f.read()
			# self.handler.print_header(fpath)
			self.parse_page(fpath, data, 1)
			self.handler.print_footer(fpath)
		except (KeyboardInterrupt, SystemExit):
			raise

	def parse(self, path):
		try:
			self.parser_func(path, 'stdin')
			return
		except (KeyboardInterrupt, SystemExit):
			raise
		except Exception as e:
			self.handler.print_error(path, e)

def extract_body(p):
	''' Extract body from the raw email '''
	if isinstance(p, str):
		return p
	else:
		return '\n'.join([extract_body(part.get_payload()) for part in p])

if __name__ == '__main__':
	data = []
	for line in fileinput.input():
		data.append(line)
	data = ''.join(data)
	msg = email.message_from_string(data)
	subject = msg['subject']
	payload = msg.get_payload()
	body = extract_body(payload)
	print "Subject: " + subject
	print body
	parser = Parser(None,'txt',None,None,'csv')
	parser.parse(body)
