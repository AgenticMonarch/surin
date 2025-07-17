"""DNS enumeration module for SURIN."""

import logging
from typing import List, Optional

from surin.core.interfaces import DiscoveryModule
from surin.utils.dns_utils import DNSUtils
from surin.utils.progress import progress_bar


class DNSEnumerationModule(DiscoveryModule):
    """Discover subdomains using DNS enumeration."""

    def __init__(self, domain: str, **kwargs):
        """Initialize DNS enumeration module.
        
        Args:
            domain: Target domain to discover subdomains for
            **kwargs: Additional configuration options
                - wordlist: Custom wordlist of subdomain prefixes
                - timeout: DNS query timeout in seconds
                - max_workers: Maximum number of concurrent DNS resolution workers
                - show_progress: Whether to show progress indicator
        """
        super().__init__(domain, **kwargs)
        self.wordlist = kwargs.get('wordlist')
        self.timeout = kwargs.get('timeout', 3)
        self.max_workers = kwargs.get('max_workers', 50)
        self.show_progress = kwargs.get('show_progress', True)
        self.dns_utils = DNSUtils(timeout=self.timeout, max_workers=self.max_workers)
        self.logger = logging.getLogger('surin.discovery.dns_enumeration')

    def discover(self) -> List[str]:
        """Execute DNS enumeration discovery.
        
        Returns:
            List of discovered subdomain names
        """
        subdomains = []
        
        # Load wordlist
        wordlist = self._load_wordlist()
        
        self.logger.info(f"Starting DNS enumeration with {len(wordlist)} subdomain patterns")
        
        # Resolve subdomains
        with progress_bar(total=len(wordlist), 
                         desc="DNS enumeration", 
                         disable=not self.show_progress) as progress:
            
            # Process subdomains in chunks to avoid overwhelming the resolver
            chunk_size = 100
            for i in range(0, len(wordlist), chunk_size):
                chunk = wordlist[i:i+chunk_size]
                results = self.dns_utils.resolve_subdomains(self.domain, chunk)
                
                for subdomain, _ in results:
                    subdomains.append(subdomain)
                
                progress.update(len(chunk))
        
        self.logger.info(f"DNS enumeration discovered {len(subdomains)} subdomains")
        return subdomains

    def _load_wordlist(self) -> List[str]:
        """Load subdomain wordlist.
        
        Returns:
            List of subdomain prefixes
        """
        if self.wordlist:
            try:
                with open(self.wordlist, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.logger.error(f"Error loading wordlist: {e}")
        
        # Default wordlist of common subdomain prefixes
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'ns3', 'ns4', 'ns5', 'ns6', 'ns7', 'ns8', 'ns9', 'ns10', 'webdisk',
            'admin', 'administration', 'administrator', 'blog', 'dashboard', 'api',
            'dev', 'development', 'staging', 'test', 'testing', 'beta', 'alpha',
            'autodiscover', 'autoconfig', 'cpanel', 'whm', 'webhost', 'secure',
            'server', 'client', 'portal', 'intranet', 'extranet', 'vpn', 'ssh',
            'sftp', 'mx', 'email', 'database', 'db', 'proxy', 'cdn', 'monitor',
            'backup', 'forum', 'shop', 'store', 'host', 'app', 'apps', 'gateway',
            'remote', 'support', 'help', 'status', 'stats', 'login', 'signup',
            'register', 'download', 'upload', 'media', 'static', 'assets', 'files',
            'docs', 'documentation', 'wiki', 'git', 'svn', 'jenkins', 'jira',
            'confluence', 'internal', 'external', 'partners', 'customers', 'cloud',
            'auth', 'sso', 'ldap', 'metrics', 'analytics', 'images', 'img', 'css',
            'js', 'javascript', 'mobile', 'm', 'api-docs', 'swagger', 'graphql',
            'rest', 'soap', 'rpc', 'web', 'service', 'services', 'public', 'private',
            'corp', 'corporate', 'lab', 'labs', 'research', 'demo', 'sandbox',
            'training', 'edu', 'education', 'learn', 'learning', 'video', 'videos',
            'stream', 'streaming', 'live', 'podcast', 'podcasts', 'audio', 'music',
            'radio', 'tv', 'news', 'events', 'calendar', 'meet', 'meeting', 'chat',
            'talk', 'conference', 'webinar', 'seminar', 'forum', 'community',
            'social', 'network', 'networks', 'connect', 'search', 'find', 'discover',
            'explore', 'browse', 'view', 'watch', 'read', 'write', 'edit', 'update',
            'create', 'new', 'old', 'archive', 'archives', 'log', 'logs', 'report',
            'reports', 'dashboard', 'control', 'panel', 'account', 'accounts',
            'billing', 'payment', 'payments', 'subscribe', 'subscription', 'plan',
            'plans', 'pricing', 'trial', 'demo', 'example', 'sample', 'test',
            'testing', 'stage', 'staging', 'production', 'prod', 'uat', 'sit',
            'dev', 'development', 'local', 'localhost', 'integration', 'ci', 'cd',
            'build', 'builder', 'studio', 'design', 'designer', 'code', 'coder',
            'developer', 'console', 'terminal', 'cmd', 'command', 'shell', 'root',
            'admin', 'administrator', 'webmaster', 'master', 'slave', 'node',
            'cluster', 'grid', 'server', 'host', 'vm', 'vps', 'instance', 'box',
            'machine', 'hardware', 'software', 'firmware', 'driver', 'drivers',
            'device', 'devices', 'printer', 'printers', 'scanner', 'scanners',
            'camera', 'cameras', 'security', 'secure', 'ssl', 'tls', 'encrypt',
            'encryption', 'decrypt', 'decryption', 'key', 'keys', 'cert', 'certs',
            'certificate', 'certificates', 'ca', 'authority', 'authorities',
            'trust', 'trusted', 'safe', 'safety', 'policy', 'policies', 'rule',
            'rules', 'law', 'laws', 'legal', 'compliance', 'compliant', 'standard',
            'standards', 'regulation', 'regulations', 'requirement', 'requirements',
            'spec', 'specs', 'specification', 'specifications', 'doc', 'docs',
            'document', 'documents', 'file', 'files', 'folder', 'folders',
            'directory', 'directories', 'path', 'paths', 'route', 'routes',
            'url', 'urls', 'uri', 'uris', 'link', 'links', 'hyperlink', 'hyperlinks',
            'web', 'website', 'webpage', 'page', 'pages', 'site', 'sites', 'cms',
            'wordpress', 'joomla', 'drupal', 'magento', 'shopify', 'wix', 'squarespace',
            'blog', 'blogger', 'wordpress', 'medium', 'tumblr', 'ghost', 'jekyll',
            'hugo', 'gatsby', 'nextjs', 'react', 'vue', 'angular', 'ember', 'svelte',
            'jquery', 'bootstrap', 'material', 'foundation', 'tailwind', 'bulma',
            'semantic', 'materialize', 'skeleton', 'pure', 'milligram', 'spectre',
            'picnic', 'chota', 'water', 'mini', 'lotus', 'siimple', 'turret',
            'cutestrap', 'concise', 'kube', 'frow', 'base', 'basscss', 'tachyons',
            'primer', 'uikit', 'ink', 'paper', 'material', 'flat', 'metro', 'win',
            'mac', 'ios', 'android', 'mobile', 'desktop', 'tablet', 'phone', 'watch',
            'tv', 'car', 'auto', 'vehicle', 'robot', 'bot', 'ai', 'ml', 'dl',
            'deep', 'learning', 'neural', 'network', 'networks', 'model', 'models',
            'train', 'training', 'predict', 'prediction', 'classify', 'classification',
            'cluster', 'clustering', 'segment', 'segmentation', 'detect', 'detection',
            'recognize', 'recognition', 'vision', 'speech', 'text', 'nlp', 'language',
            'translate', 'translation', 'understand', 'understanding', 'generate',
            'generation', 'create', 'creation', 'synthesize', 'synthesis', 'analyze',
            'analysis', 'process', 'processing', 'compute', 'computing', 'calculate',
            'calculation', 'math', 'mathematics', 'statistic', 'statistics', 'data',
            'big', 'small', 'medium', 'large', 'huge', 'tiny', 'mini', 'micro',
            'nano', 'pico', 'mega', 'giga', 'tera', 'peta', 'exa', 'zetta', 'yotta'
        ]