"""
Mumble Link Bot
----------------

Connects to a Murmur (Mumble) server via Ice and listens for text messages.
When a message contains one or more URLs, the bot rewrites them to remove
tracking parameters based on rules loaded from a JSON config file, and replies
with the cleaned links.

Configuration file (JSON) example (links-config.json):

{
  "global_strip_params": ["utm_*", "gclid", "fbclid", "mc_eid", "mc_cid", "igshid"],
  "domains": {
	"youtube.com": {"remove_all_params": false, "allowed_params": ["v", "t"]},
	"youtu.be": {"remove_all_params": false, "allowed_params": ["t"]},
	"twitter.com": {"remove_all_params": true},
	"x.com": {"remove_all_params": true},
	"reddit.com": {"remove_all_params": true},
	"amazon.*": {"remove_all_params": false, "allowed_params": ["k", "s"]}
  }
}

Rules:
- global_strip_params: wildcard list; any matching query keys are removed for all domains.
- domains[host]: supports exact host or wildcard like "amazon.*".
  - remove_all_params: if true, all query params are removed for matching host.
  - allowed_params: if provided and remove_all_params is false, only these params remain.

Notes:
- This script is intentionally minimal and uses the Ice/MumbleServer bindings present
  in this repository (see channel_push.py for reference). No external deps needed.
"""

import re
import os
import json
import logging
import argparse
from typing import Dict, List, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import html

import Ice
import MumbleServer

# Logging setup similar to channel_push.py
logger = logging.getLogger(__name__)

LOG_LEVELS = {
	'CRITICAL': logging.CRITICAL,
	'ERROR': logging.ERROR,
	'WARNING': logging.WARNING,
	'INFO': logging.INFO,
	'DEBUG': logging.DEBUG,
	'NOTSET': logging.NOTSET,
}

def configure_logging(level_str: str | None = None) -> None:
	if level_str is None:
		level = logging.INFO
	else:
		level = LOG_LEVELS.get(level_str.upper(), logging.INFO)

	root = logging.getLogger()
	if not root.handlers:
		handler = logging.StreamHandler()
		formatter = logging.Formatter(
			fmt='%(asctime)s %(levelname)s [%(name)s] %(message)s',
			datefmt='%Y-%m-%d %H:%M:%S'
		)
		handler.setFormatter(formatter)
		root.addHandler(handler)
	root.setLevel(level)
	logger.setLevel(level)

MAX_MESSAGE_LENGTH = 5000

# ----------------------
# Config loading & rules
# ----------------------

class LinkRules:
	def __init__(self, config: Dict):
		self.global_strip: List[str] = config.get('global_strip_params', [])
		self.domains: Dict[str, Dict] = config.get('domains', {})

	def match_domain_rule(self, host: str) -> Dict | None:
		"""Find a domain rule by exact match or wildcard (e.g., example.*).
		Returns the matching rule dict or None.
		"""
		# Build candidate hosts to match: exact host, host without leading 'www.', and base domain (last two labels)
		labels = host.split('.')
		candidates = [host]
		if host.startswith('www.'):
			candidates.append(host[4:])
		if len(labels) >= 2:
			candidates.append('.'.join(labels[-2:]))  # e.g., amazon.com

		for cand in candidates:
			# Exact match first
			if cand in self.domains:
				return self.domains[cand]
			# Wildcard match like "amazon.*" -> regex ^amazon\..*$
			for pattern, rule in self.domains.items():
				if '*' in pattern:
					regex = '^' + re.escape(pattern).replace("\\*", '.*') + '$'
					if re.match(regex, cand):
						return rule
		return None

	@staticmethod
	def _wildcard_matches(patterns: List[str], key: str) -> bool:
		for p in patterns:
			if '*' in p:
				regex = '^' + re.escape(p).replace("\\*", '.*') + '$'
				if re.match(regex, key):
					return True
			else:
				if key == p:
					return True
		return False

	def clean_url(self, url: str) -> Tuple[str, bool]:
		"""Return (cleaned_url, changed_flag)."""
		try:
			parsed = urlparse(url)
			if not parsed.scheme or not parsed.netloc:
				return url, False

			host = parsed.netloc.lower()
			rule = self.match_domain_rule(host)

			# Current query pairs
			query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

			if not query_pairs:
				# Nothing to clean
				return url, False

			if rule and rule.get('remove_all_params'):
				new_pairs: List[Tuple[str, str]] = []
			else:
				allowed = set(rule.get('allowed_params', [])) if rule else set()
				# Remove global strip matches and anything not explicitly allowed if allowed list provided
				new_pairs = []
				for k, v in query_pairs:
					if self._wildcard_matches(self.global_strip, k):
						continue
					if allowed:
						if k in allowed:
							new_pairs.append((k, v))
					else:
						# No allow-list: keep if not globally stripped
						new_pairs.append((k, v))

			new_query = urlencode(new_pairs, doseq=True)
			if new_query == parsed.query:
				return url, False

			cleaned = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
			return cleaned, True
		except Exception:
			logger.exception("Failed to clean URL: %s", url)
			return url, False


def load_config(path: str | None) -> LinkRules:
	default_paths = [
		path,
		os.environ.get('LINK_BOT_CONFIG'),
		os.path.join(os.getcwd(), 'links-config.json'),
	]
	for p in default_paths:
		if not p:
			continue
		if os.path.isfile(p):
			with open(p, 'r', encoding='utf-8') as f:
				cfg = json.load(f)
			logger.info("Loaded link rules from %s", p)
			return LinkRules(cfg)
	logger.warning("No config file found; using default minimal rules")
	return LinkRules({
		'global_strip_params': ['utm_*', 'gclid', 'fbclid', 'mc_eid', 'mc_cid', 'igshid'],
		'domains': {
			'youtube.com': {'allowed_params': ['v', 't'], 'remove_all_params': False},
			'youtu.be': {'allowed_params': ['t'], 'remove_all_params': False},
			'twitter.com': {'remove_all_params': True},
			'x.com': {'remove_all_params': True},
		}
	})


# ----------------------
# Mumble ICE integration
# ----------------------

URL_REGEX = re.compile(r"(https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+)")


class LinkBotCallback(MumbleServer.ServerCallback):
	def __init__(self, server: MumbleServer.ServerPrx, rules: LinkRules):
		self.server = server
		# Attempt to obtain server id; handle unreachable proxy gracefully
		try:
			self.server_id = server.id()
		except Ice.ConnectFailedException as e:
			# Mark as unknown; caller should have skipped registering callback
			logger.error("Server proxy unreachable when fetching id: %s", e)
			self.server_id = -1
		self.rules = rules

	# Only implement text message handling; other events can be ignored
	def userTextMessage(self, user, message, current=None):
		try:
			
			text = message.text or ''
			# skip very long messages
			if len(text) > MAX_MESSAGE_LENGTH:
				logger.debug(f"Message too long ({len(text)}>{MAX_MESSAGE_LENGTH} characters); skipping", len(text))
				return
			# Normalize HTML-escaped content (e.g., '&amp;') to plain text before URL extraction
			try:
				text = html.unescape(text)
			except Exception:
				pass

			# If the client sent HTML anchors, extract hrefs and strip tags
			href_urls = []
			if '<a ' in text:
				try:
					# Extract href="..." values
					for m in re.finditer(r'href="([^"]+)"', text):
						href_urls.append(m.group(1))
					# Do not rely on anchor body; we will use hrefs exclusively to avoid duplicates
				except Exception:
					pass
			logger.debug("Received message from user %s on server %s: %s", user.name, self.server_id, text)
			# Prefer hrefs when present; else fall back to plain-text URL detection
			urls = href_urls if href_urls else URL_REGEX.findall(text)
			logger.debug("Extracted %d URL(s): %s", len(urls), urls)
			if not urls:
				return

			cleaned_pairs = []
			for u in urls:
				# Also unescape any entity-encoded pieces inside individual URLs
				try:
					import html as _html
					u = _html.unescape(u)
				except Exception:
					pass
				cu, changed = self.rules.clean_url(u)
				if changed:
					cleaned_pairs.append((u, cu))
					logger.debug("Cleaned URL: %s -> %s", u, cu)
				else:
					logger.debug("URL unchanged (skipped): %s", u)

			if not cleaned_pairs:
				logger.debug("No URLs required cleaning; not sending a reply")
				return

			# Prepare a friendly reply to the channel the message was sent to
			# message.channels is a sequence of channel IDs
			channel_ids = list(message.channels or [])
			# Build HTML reply so links are clickable
			reply_lines = ["<p>Cleaned links:</p>", "<ul>"]
			for orig, cleaned in cleaned_pairs:
				reply_lines.append(f"<li><a href=\"{cleaned}\">{cleaned}</a></li>")
			reply_lines.append("</ul>")
			reply_text = "".join(reply_lines)

			if channel_ids:
				# Send only to the original channel (first in list)
				cid = channel_ids[0]
				try:
					self.server.sendMessageChannel(cid, False, reply_text)
					logger.debug("Sent reply to channel %s", cid)
				except Exception:
					logger.exception("Failed to send message to channel %s", cid)
			else:
				# Fallback: use the user's current channel if available
				cid = getattr(user, 'channel', None)
				if cid is not None:
					try:
						self.server.sendMessageChannel(cid, True, reply_text)
						logger.debug("Sent reply to user's current channel %s", cid)
					except Exception:
						logger.exception("Failed to send message to user's channel %s", cid)
				else:
					logger.debug("No channel context found; not sending a direct user message per policy")
		except Exception:
			logger.exception("Error handling userTextMessage")

	def userConnected(self, state, current=None):
		# stub, not used
		pass
	def userDisconnected(self, state, current=None):
		# stub, not used
		pass
	def userStateChanged(self, state, current=None):
		# stub, not used
		pass
	def channelCreated(self, state, current=None):
		# stub, not used
		pass
	def channelRemoved(self, state, current=None):
		# stub, not used
		pass
	def channelStateChanged(self, state, current=None):
		# stub, not used
		pass

def initialize_and_run(args):
	# Ice init
	prop = Ice.createProperties([])
	prop.setProperty("Ice.ImplicitContext", "Shared")
	prop.setProperty("Ice.MessageSizeMax", "65535")

	idd = Ice.InitializationData()
	idd.properties = prop
	ic = None

	try:
		ic = Ice.initialize(idd)
		ic.getImplicitContext().put("secret", args.secret)

		constring = f"Meta -e 1.0:tcp -h {args.host} -p {args.port}"
		prx = ic.stringToProxy(constring)
		prx.ice_ping()
		logger.info("Connected to Murmur Meta on %s:%s", args.host, args.port)

		meta = MumbleServer.MetaPrx.checkedCast(prx)
		booted = meta.getBootedServers()
		if not booted:
			logger.warning("No booted servers found; exiting")
			return 1

		rules = load_config(args.config)

		# Create adapter for callbacks (explicit port optional)
		endpoint = f"tcp -h {args.ice_host}" + (f" -p {args.ice_callback_port}" if args.ice_callback_port else "")
		adapter = ic.createObjectAdapterWithEndpoints("LinkBot.Client", endpoint)
		adapter.activate()
		logger.debug("found %d booted servers", len(booted))

		# Register callbacks for each server
		for server in booted:
			# Probe server reachability before full registration
			try:
				# Debug: show raw proxy endpoints before invoking any ops
				if args.debug_endpoints:
					try:
						logger.debug("Server proxy string: %s", server.ice_toString())
						for ep in server.ice_getEndpoints():
							logger.debug("  endpoint: %s", ep.toString())
					except Exception:
						logger.debug("Failed to enumerate endpoints for server proxy")

				# Attempt initial id() call; if unreachable and override provided, rewrite proxy and retry
				try:
					sid = server.id()
				except Ice.ConnectFailedException as first_err:
					if args.override_server_host:
						orig = server.ice_toString()
						# Rewrite all occurrences of '-h OLDHOST' to new host; optionally port
						import re as _re
						new = _re.sub(r"(-h\s+)([^\s]+)", f"\\1{args.override_server_host}", orig)
						if args.override_server_port:
							new = _re.sub(r"(-p\s+)(\d+)", f"\\1{args.override_server_port}", new)
						logger.warning("Server proxy unreachable (%s); retrying with rewritten proxy: %s", first_err.__class__.__name__, new)
						try:
							server = MumbleServer.ServerPrx.checkedCast(ic.stringToProxy(new)) or server
							sid = server.id()
							logger.info("Rewritten proxy succeeded for server id=%s", sid)
						except Exception:
							logger.error("Rewritten proxy also failed; skipping server")
							continue
					else:
						logger.error("Cannot reach server proxy and no override provided; skipping")
						continue

				host_conf = None
				port_conf = None
				try:
					host_conf = server.getConf('host')
					port_conf = server.getConf('port')
				except Exception:
					pass
				servant = LinkBotCallback(server, rules)
				if servant.server_id == -1:
					logger.warning("Skipping unreachable server proxy returned by Meta (sid tentative: %s)", sid)
					continue
				ident = Ice.stringToIdentity(f"linkbot-cb-{sid}")
				cb_prx = MumbleServer.ServerCallbackPrx.uncheckedCast(adapter.add(servant, ident))
				server.addCallback(cb_prx)
				logger.info(
					"LinkBot registered on server %s (conf host=%s port=%s, callback endpoint=%s)",
					sid, host_conf, port_conf, endpoint
				)
			except Ice.ConnectFailedException as e:
				logger.error("Cannot reach server proxy from container (ConnectFailed): %s. Skipping. (line %d)", e, e.__traceback__.tb_lineno)
			except Exception:
				logger.exception("Unexpected error while registering callback; skipping server")

		# Keep process alive to receive callbacks
		logger.info("LinkBot is now listening for messages...")
		try:
			# Block the main thread; Ice will process callbacks
			import signal
			signal.pause()
		except KeyboardInterrupt:
			pass
		return 0
	except MumbleServer.InvalidSecretException:
		logger.error("Invalid secret provided. Check --secret or MUMBLE_ICE_SECRET.")
		return 2
	except Exception:
		logger.exception("Fatal error initializing Link Bot")
		return 3
	finally:
		try:
			if ic:
				ic.destroy()
		except Exception:
			pass


def parse_args():
	parser = argparse.ArgumentParser(description='Mumble Link Bot - rewrite links to remove tracking params')
	parser.add_argument('--host', default=os.environ.get('MUMBLE_ICE_HOST', 'localhost'),
						help='Ice host (default env MUMBLE_ICE_HOST or localhost)')
	parser.add_argument('--port', type=int, default=int(os.environ.get('MUMBLE_ICE_PORT', '6502')),
						help='Ice port (default env MUMBLE_ICE_PORT or 6502)')
	parser.add_argument('--secret', default=os.environ.get('MUMBLE_ICE_SECRET', ''),
						help='Ice secret (default env MUMBLE_ICE_SECRET)')
	parser.add_argument('--ice-callback-host', default=os.environ.get('ICE_CALLBACK_HOST', 'localhost'),
						help='Ice callback host/IP for Murmur to connect back (default env ICE_CALLBACK_HOST or localhost)')
	parser.add_argument('--ice-callback-port', type=int, default=int(os.environ.get('LINK_BOT_CALLBACK_PORT', '0')),
						help='Optional fixed TCP port for callback adapter (0 => random ephemeral).')
	parser.add_argument('--config', default=os.environ.get('LINK_BOT_CONFIG'),
						help='Path to JSON config with link rules (default env LINK_BOT_CONFIG or ./links-config.json)')
	parser.add_argument('--log-level', default=os.environ.get('LINK_BOT_LOG_LEVEL', 'INFO'),
						help='Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)')
	parser.add_argument('--debug-endpoints', action='store_true',
						help='Log raw Ice proxy endpoint strings for each server to aid SSH tunnel setup.')
	parser.add_argument('--override-server-host', default=os.environ.get('LINK_BOT_OVERRIDE_HOST'),
						help='If set, rewrite returned server proxies to use this host when initial connect fails.')
	parser.add_argument('--override-server-port', type=int, default=int(os.environ.get('LINK_BOT_OVERRIDE_PORT', '0')),
						help='If >0 and server proxy unreachable, also rewrite its port to this value.')
	parser.add_argument('--max-message-length', type=int, default=int(os.environ.get('LINK_BOT_MAX_MESSAGE_LENGTH', '5000')),
                        help='Maximum length of incoming messages to process (default 5000)')
	args = parser.parse_args()
	MAX_MESSAGE_LENGTH = args.max_message_length
	return args


def main():
	args = parse_args()
	configure_logging(args.log_level)
	logger.info("Starting Link Bot")
	rc = initialize_and_run(args)
	return rc


if __name__ == '__main__':
	raise SystemExit(main())

