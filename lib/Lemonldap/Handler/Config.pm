package Lemonldap::Handler::Config;
use strict;
use constant DEBUG=>1;
use XML::Simple;
use Data::Dumper;
use LWP::UserAgent ();
use IPC::Shareable qw(:lock);
use Lemonldap::Handler::Intrusion;
use Lemonldap::Crypto;
use Digest::MD5 qw(md5);
# Later, this will be embedded in the XML configuration file
our %corresp = ( '%m' => 'mail', '%d' => 'dn', '%c' => 'cn', '%u' => 'uid' );

sub new {
	my ($proto,$r)=@_;
	my $class = ref($proto) || $proto;

	my $self;

	my %CONFIG;
	die "Impossible d'accéder à la mémoire partagée"
		unless tie %CONFIG, 'IPC::Shareable',
			{key => $r->dir_config("LemonldapConfigNameSpace") || "LEMO",
			create => 1, mode => 0660, destroy => 1,
			size => $r->dir_config("LemonldapConfigShmSize") || IPC::Shareable::SHM_BUFSIZ()
			};
	$self->{share}=\%CONFIG;
	$self->{serial}=0;

	$self->{handler_id} = $r->dir_config("LemonldapHandlerId");
	$self->{manager_url} = $r->dir_config("LemonldapManagerUrl");
	$self->{key} = md5($r->dir_config("LemonldapSharedSecret"));
	print "HandlerId: ".$self->{handler_id}
		."\nManagerUrl: ".$self->{manager_url}
		."\nSecret: ".$r->dir_config("LemonldapSharedSecret") if(DEBUG);
	$self->{crypto} = new Lemonldap::Crypto ({ key => $self->{key}, cipher => 'Blowfish' });
	$self->{lastcheck} = 0;
	$self->{delay_update} = $r->dir_config("LemonldapConfigUpdate") || 120;
	$self->{notice} = $r->dir_config("LemonldapNotify") || 0;
	$self->{intrusion_process} = $Lemonldap::Handler::Intrusion::response{
					$r->dir_config("LemonldapIntrusionProcess") || "forbidden"
					};
	$self->{stop_cookie} = $r->dir_config("LemonldapStopCookie") || 0;
	$self->{enable_proxy} = $r->dir_config("LemonldapEnableProxy") || 0;
	bless $self, $class;
	return $self;
}

sub refresh_config {
	my $self=shift;
	print STDERR "Refresh\n" if(DEBUG);
	$self->retr_config unless($self->{share}->{status});
	return $self->init unless(
		((time - $self->{lastcheck}) > $self->{delay_update})
		and ($self->{serial} eq $self->{share}->{serial})
		);
	return 1;
}

sub child_query {
	my $self = shift;
	my($command) = @_;
	my $request = HTTP::Request->new(POST => $self->{manager_url});
	my $buf = "handler=".$self->{handler_id}
		."&requete=$command&signature=".$self->{crypto}->sign($self->{handler_id}." ".$command);
	print STDERR "Request parameters: $buf\n" if(DEBUG);
	$request->header("Content-Length" => length($buf));
	$request->content($buf);
	$request->content_type("application/x-www-form-urlencoded");
	my $UA = new LWP::UserAgent(keep_alive => 0);
	my $response = $UA->request($request);
	my $signature = $response->header('Signature');
	my $content = $response->content;
	print STDERR "Contenu $content \nCode ".$response->code."\nMessage ".$response->message."\n" if DEBUG;
	return $content if ($response->code==200 and $self->{crypto}->sign_verify($content,$signature));
	return 0;
}

sub retr_config {
	my $self = shift;
	print STDERR "Recuperation de la configuration\n" if(DEBUG);
	my $handler_config = $self->child_query('config');
	#Stockage en mémoire partagée
	if($handler_config){
		# Non-bloquing call
		if(tied(%{$self->{share}})->shlock(LOCK_SH|LOCK_NB)){
			$self->{share}->{serial}++;
			$self->{share}->{config} = $handler_config;
			$self->{share}->{status}=1;
			tied(%{$self->{share}})->shunlock;
			print STDERR "Config stored in IPC cache\n" if(DEBUG);
		}else{
			# In this case, we have the configuration, but
			# another child is going to create the cache
			# so we can initialize local conf
			$self->_process($handler_config);
			print STDERR "Can't store config in IPC cache\n" if(DEBUG);
		}
	}else{
		print STDERR "Impossible d'obtenir la configuration\nConf: $handler_config\n"."\n";
	}
}

sub init {
	my($self)=@_;
	print STDERR "My Serial Number ".$self->{serial}." (Config is ".$self->{share}->{serial}.")\n" if(DEBUG);
	print STDERR "Configuration (re)initialization\n" if(DEBUG);
	my $handler_config = $self->{share}->{config};
	if($handler_config){
		return $self->_process($handler_config);
	}
	# Problem, the share has no config: this can be a lost
	# so to avoid "Error 500", we return OK if we have a
	# valid configuration.
	return 1 if($self->{serial});
	# TODO : Change this using a dedicated Apache variable (LemonldapStrict)
}
sub _process {
	my($self,$handler_config)=@_;
	$handler_config = XMLin($handler_config,(forcearray=>1,keyattr => "id"));
	print STDERR "Handler_config : ".Dumper($handler_config) if(DEBUG);
	# base_url may not finish by /
	$handler_config->{base_url} =~ s#/$##;
	$handler_config->{real_base_url} =~ s#/$##;
	# Verrouillage du cache des informations
	foreach (qw(base_url real_base_url datasource datauser datapass cookie_name)) {
		$self->{$_} = $handler_config->{$_};
	}

	foreach my $s (keys %{$handler_config->{section}}) {
		# Now, we're going to pre-compile a regexp contening all
		# group ids authorized to access this section
		my $tmp;
		print STDERR "Config: Section: ".Dumper($handler_config->{section}->{$s}) if(DEBUG);
		foreach (keys %{$handler_config->{section}->{$s}->{auto}}) {
			$tmp.=$handler_config->{section}->{$s}->{auto}->{$_}->{group}.'|';
		}
		$tmp =~ s/\|$//;
		print STDERR "Regexp auto: $tmp\n" if(DEBUG);
		$handler_config->{section}->{$s}->{auto_c}=qr/$tmp/;
		$handler_config->{section}->{$s}->{regexp} =~ s/^[\^\/]*//;
		$handler_config->{section}->{$s}->{regexp} =~ s/[\$]$//;
	}
	$self->{sections} = $handler_config->{section};
	# Creation of header template
	my $tmp="";
	# TODO: verify applications.xml headers description
	foreach (keys %{$handler_config->{header}}) {
		$tmp.=$handler_config->{header}->{$_}->{header}.";".
			$handler_config->{header}->{$_}->{value}.";";
	}
	$self->{header_template} = $tmp;
	print STDERR "Headers: ".Dumper($self->{header_template}) if(DEBUG);
	$self->{serial} = $self->{share}->{serial};
	$self->{lastcheck} = time;
	return 1;
}
sub get_regexp_user {
	my $self = shift;
	my($groups) = @_;
	my $r = "(";
	foreach (keys %{$self->{sections}}) {
		print STDERR "No compiled regexp for section"
				.Dumper($self->{sections}->{$_})
			if(DEBUG and !defined($self->{sections}->{$_}->{auto_c}));
		$r .= "(".$self->{sections}->{$_}->{regexp}.")|"
			if($groups =~ $self->{sections}->{$_}->{auto_c});
	}
	$r =~ s/\|$/\)/;
	$r.=")";
	$r =~ s/\(\)//g;
	return '^/'.$r.'$';
}
sub get_portal {
	my $self = shift;
	my($url) = @_;
	print STDERR "Try to get the portal\n" if(DEBUG);
	foreach (keys %{$self->{sections}}) {
		print STDERR "No regexp\n" if(DEBUG and !defined($self->{sections}->{$_}->{regexp}));
		my $tmp=$self->{sections}->{$_}->{regexp};
		return $self->{sections}->{$_}->{portal} if($url =~ /$tmp/);
	}
	print STDERR "$url ne correspond à aucune section\n";
	return 0;
}
sub header_spec {
	my $self = shift;
	my(%session)=@_;
	my $h = $self->{header_template};
	foreach (keys(%corresp)){
		my $tmp = $session{$corresp{$_}};
		$h =~ s/$_/$tmp/g;
	}
	return $h;
}
1;
