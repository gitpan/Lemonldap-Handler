package Lemonldap::Handler;

# CONSTANTS
use constant DEBUG => 1;

use lib qw(/etc/lemonldap);
use strict;

# modperl
use Apache ();
use Apache::URI();
use Apache::Constants qw(:common :response);
use Apache::Session::MySQL;
use Apache::ModuleConfig;

use MIME::Base64;
use LWP::UserAgent;

use Lemonldap::Handler::Config;
use Lemonldap::Handler::IpcSharedUsers;

if(DEBUG) {
	use Data::Dumper;
}
our ($VERSION, @EXPORTS);

$VERSION = "0.01";

our $share;
our $config;
our $UA;

# $client, $urlReg, $headers sont des variables du fils en cours
# elles évite de consulter le cache lorsque le client reste le
# même pour un fils d'Apache (fréquent en HTTP/1.1)
# la seule différence entre ces variables et le cache IPC client
# vient du fait que les regexp ne peuvent être compilées dans les IPC
our ($client,$uid,$urlReg,$headers,$trace);

Apache->push_handlers( PerlChildInitHandler=>\&childInit );

$|=1 if(DEBUG);
# The Init phase isn't called before the Apache's fork process to
# avoid privilege problems: IPC's shares are created under the good uid
sub childInit {
	my $r=shift;
	print STDERR "Child init\n" if(DEBUG);
	$config = new Lemonldap::Handler::Config($r);
	$share = new Lemonldap::Handler::IpcSharedUsers($config,$r);
	if($config->{enable_proxy}){
		$UA = LWP::UserAgent->new;
		$UA->agent(join "/", "LWP::UserAgent", $VERSION);
	}
	return OK;
}

# Main handler: called with PerlInitHandler if possible:
#   - first handler phase if called outside of <Location>
#   - just after TransHandler process if called in <Location>
#     to use Alias process or mod_rewrite
# If you want to use mod_rewrite before calling Lemonldap,
# use PerlHeaderParseHandler instead
sub handler {
	my $r=shift;
	# If wanted, we called built-in proxy
	if($config->{enable_proxy}) {
		$r->handler("perl-script");
		$r->push_handlers( PerlHandler => \&proxy_handler );
	}
	# Stop if protection is disabled
	return DECLINED if($r->dir_config("LemonldapDisabled"));
	# is this area protected
	# configuration check
	return SERVER_ERROR unless($config->refresh_config);


	# AUTHENTICATION
	# cookie search
	my %entete =$r->headers_in();
	my $cookie_name = $config->{cookie_name};
	my $idx =$entete{'Cookie'} ;
	# Load id value from cookie
	$idx =~ /$cookie_name=([^; ]+)(;?)/o;
	my $id =$1;
	unless ($id) {
		# No cookie found: redirect to portal
		print STDERR "lemon_handler: No cookie found for ".$r->uri."\n" if(DEBUG);
		return goPortal($r);
	}
	print STDERR "lemon_handler: id session : $id ---  $idx\n" if(DEBUG);
	# SESSIONS CACHE 
	#      - level 1: local cache ($client,$urlReg,$headers,$trace)
	#      - level 2: IPC shared cache (apache's children) (objet $share)
	#      - level 3: central cache - called with getFromCache()

	# level 1 test
	unless($id eq $client){
		# Level 2 test
		print STDERR "Searching client in IPC cache...\n" if(DEBUG);
		($client,$uid,$urlReg,$headers,$trace) = ($share->get($id));
		unless($trace) {
			# Level 3: call central cache (see bellow)
			print STDERR "Searching client in central cache...\n" if(DEBUG);
			my %datas = getFromCache($r,$id);
			unless (%datas) {
				# Session lost ?
				return goPortal($r);
			}
			print SDTERR "First access on area protected by Lemonldap ( "
				.$config->{handler_id}." by $trace\n" if($config->{notice});
			# Now we've to store $datas in the IPC cache
			# ... and initialize local variables
			print STDERR "Trying to store client in IPC cache...\n" if(DEBUG);
			$share->store(%datas);
			($client,$uid,$urlReg,$headers,$trace) = $share->get($id);
			print STDERR "Client is $trace identified by $client\n" if(DEBUG);
		}else{
			print STDERR "Client $trace found in cache\n" if(DEBUG);
		}
	}else{
		print STDERR "New request from client $trace\n" if(DEBUG);
	}
	# AUTHORIZATION
	# $urlReg contains a pre-compiled regexp used to verifie
	# the rights
	my $uri = $r->uri.($r->args?"?".$r->args:"");
	unless($uri =~ $urlReg){
		print STDERR "Intrusion: $trace has called $uri\n" if(DEBUG || $config->{notice});
		# Intrusion module has to generate the response
		$r->handler("perl-script");
		$r->push_handlers(PerlHandler => \&$config->{intrusion_process});
		return OK;
	}

	# Now all is good, we can insert client headers
	print STDERR "lemon_handler: Request $uri ($trace)\n" if (DEBUG);
	foreach (keys(%{$headers})) {
		$r->header_in($_=>$headers->{$_});
	}
	print STDERR "lemon_handler: headers\n".Dumper($headers) if (DEBUG);

	# STOP_COOKIE is used to hide cookie value to the remote application
	# (to avoid programmers to usurp client identities)
	if($config->{stop_cookie}) {
		$r->headers_in->do(sub { 
			(my $cle ,my $valeur) = @_;
			if ($valeur=~ /$cookie_name/o) {
				my $tmp =~ /$cookie_name=.+b/o;
				$_[1]=~ s/$tmp//;
				print STDERR "lemon_handler: STOP_COOKIE done\n" if (DEBUG); 
			}     
			1;
		});
	}
	# This is used to store uids as connected users in Apache's logs
	$r->connection->user($trace);
	# IPC clean up (see bellow)
	$r->push_handlers( PerlCleanUpHandler=>\&cleanup );
	return OK;
}

# We want IPC cache to be cleaned up and configuration to be refresh.
# Configuration stored in IPC cache may be changed
# this sub is called AFTER pulling the wanted page for performances.
sub cleanup {
	$config->init;
	$share->cleanup;
}

sub proxy_handler {
	my $r = shift;
	# Transformation: GET /index.html becomes http://servername/index.html
	# $url contains the real value (hided server)
	# $url_init contains the asked value
	my $url =$r->uri.($r->args?"?".$r->args:""); 
	my %entete = $r->headers_in();
	my $url_init= $config->{base_url}.$url;
	$url = $config->{real_base_url}.$url;

	my $request = HTTP::Request->new($r->method, $url);
	$r->headers_in->do(sub { 
		$request->header(@_);
		1;
	});
	# copy POST data, if any
	if($r->method eq 'POST') {
		my $len = $r->header_in('Content-length');
		my $buf;
		$r->read($buf, $len);
		$request->content($buf);
		$request->content_type($r->content_type);
	}

	print STDERR  "lemon_handler: request ".$request->as_string()."\n" if(DEBUG);

	# LWP proxy
	my $response = $UA->request($request);
	$r->content_type($response->header('Content-type'));

	$r->status($response->code);
	$r->status_line(join " ", $response->code, $response->message);
	$response->scan(sub {
		$r->header_out(@_);
		});

	if ($r->header_only) {
		$r->send_http_header();
		return OK;
	}

	my $content = \$response->content;
	$r->content_type('text/html') unless $$content;
	$r->send_http_header;
	$r->print($$content || $response->error_as_HTML);
	print STDERR "lemon_handler: response sent\n"  if (DEBUG); 

	return OK;
}
sub goPortal {
	my ($r,$id)=@_;
	my $urlc_init = encode_base64($config->{base_url}.$r->uri.($r->args?"?".$r->args:""));
	$urlc_init=~ s/\n//g;
	$r->header_out(location =>$config->get_portal($r->uri)."?op=c&url=$urlc_init");
	print STDERR "Redirect to portal (url was ".$r->uri.")\n" if(DEBUG);
	return REDIRECT;
}
sub getFromCache {
	my ($r,$id)=@_;
	my %session;
	# Now we're trying to fetch session informations from the central cache
	eval {
		tie %session, 'Apache::Session::MySQL', $id, {
			DataSource     => $config->{datasource},
			UserName       => $config->{datauser},
			Password       => $config->{datapass},
			LockDataSource => $config->{datasource},
			LockUserName   => $config->{datauser},
			LockPassword   => $config->{datapass},
		};
	};

	# In case of error, $@ contains a message
	if( $@ )  {
		print STDERR "lemon_handler: Error from central cache $@\n"  if(DEBUG);
		return;
	}
	# In the case bellow, the user has a cookie, but it isn't valid. The session
	# may have expired.
	# TODO: when we'll use a ciphered cookie, we'll be able to distinguish an attacker
	#       trying a random session.
	if( keys(%session) eq 0 ) {
		return goPortal($r);
	}

	print STDERR "lemon_handler: session ".Dumper(\%session) if(DEBUG);
	my %data = %session;
	untie %session;
	return ((id=>$id),%data);
}
1;
__END__

=head1 NAME

Lemonldap::Handler - Apache/modperl module to implement a Lemonldap
compatible SSO agent.

=head1 SYNOPSIS

httpd.conf:

  PerlModule Lemonldap::Handler

  # Required directives
  PerlSetVar LemonldapManagerUrl    https://portal/manager.pl
  PerlSetVar LemonldapSharedSecret  <My key>
  PerlSetVar LemonldapHandlerId     <Handler Id>

  # To use the built-in  proxy
  PerlSetVar LemonldapEnableproxy   1

  # Common usage
  <VirtualHost *:443>
    # Enabling protection
    PerlInitHandler Lemonldap::Handler

    # Example of disabling authentication
    <Files *.jpg>
      PerlSetVar LemonldapDisabled 1
    </Files>
  </VirtualHost>

=head1 DESCRIPTION

Lemonldap is a collection of Perl modules written to implement a complete
solution of web single sign on (Web-SSO).

This module provides an Apache module which can bu used to protect a web
directory.

=head1 ADVANCED USAGE

Lemonldap::Handler has several others parameters:

=head2 Using several instances

If you want to use more than one instance (several VirtualHosts for example,
you have to set a different SHM namespace for the configuration store and
users store. Those names must consist of four alphanumerics:

  <VirtualHost 1>
    PerlInitHandler Lemonldap::Handler
    PerlSetVar LemonldapConfigNameSpace LC01
    PerlSetVar LemonldapUsersNameSpace  LU01
  </VirtualHost>
  <VirtualHost 2>
    PerlInitHandler Lemonldap::Handler2
    PerlSetVar LemonldapConfigNameSpace LC02
    PerlSetVar LemonldapUsersNameSpace  LU02
  </VirtualHost>

B<NOTE>: Lemonldap::Handler2 can be a simple copy of original package to avoid
variable conflicts.

=head2 Logging

Lemonldap::Handler inform Apache of connected users for logging. In
complement, it can generate a special log for the first access:

  PerlSetVar LemonldapNotify 1

=head2 Protecting user cookies

By default, Lemonldap::Handler transmits the user request to the remote
application. If you want to hide the cookie to avoid programmers to usurp
any identity, Lemonldap::Handler can do it:

  PerlSetVar LemonldapStopCookie 1

=head2 Notify unauthorizated requests

By default, Lemonldap::Handler call the Lemonldap::Handler::Intrusion sub
called forbidden which deny just the request. See
Lemonldap::Handler::Intrusion(3) for other available subroutines.

Exemple :

  PerlSetVar LemonldapIntrusionProcess mail

=head2 Tuning the shared cache

Lemonldap::Handler use some shared memory to share users informations between
all Apache's children. By defaults, this size is set to 65535. To increase it:

  PerlSetVar LemonldapUsersShmSize  131069
  PerlSetVar LemonldapConfigShmSize 131069

By default, each Apache's child check the shared configuration each 120
seconds. You can change this value:

  PerlSetVar LemonldapConfigUpdate 240

=head1 SEE ALSO

Lemonldap(3), Lemonldap::Handler::Intrusion(3)

http://lemonldap.sourceforge.net/

"Writing Apache Modules with Perl and C" by Lincoln Stein E<amp> Doug
MacEachern - O'REILLY

=head1 AUTHORS

=over 1

=item Eric German, E<lt>germanlinux@yahoo.frE<gt>

=item Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=back

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by Eric German E<amp> Xavier Guimard

Lemonldap originaly written by Eric german who decided to publish him in 2003
under the terms of the GNU General Public License version 2.

=over 1

=item This library is under the GNU General Public License, Version 2.

=item The primary copyright holder is Eric German.

=item Portions are copyrighted under the same license as Perl itself.

=item Portions are copyrighted by Doug MacEachern and Lincoln Stein.

=back

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 dated June, 1991.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  A copy of the GNU General Public License is available in the source tree;
  if not, write to the Free Software Foundation, Inc.,
  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

=cut
