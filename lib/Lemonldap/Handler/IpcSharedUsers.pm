package Lemonldap::Handler::IpcSharedUsers;
use strict;
use IPC::Shareable;
use constant DEBUG=>1;
use Data::Dumper;

our %SHARE;
sub new {
	my ($proto,$config,$r)=@_;
	my $class = ref($proto) || $proto;
	die "Unable to access to sharde memory"
		unless tie %SHARE, 'IPC::Shareable',
			{key => $r->dir_config("LemonldapUsersNamespace"),
			create => 1, mode => 0660, destroy => 1,
			size => $r->dir_config("LemonldapUserShmSize") || IPC::Shareable::SHM_BUFSIZ()
			};
	my $self;
	$self->{config}=$config;
	$self->{max_size}=$r->dir_config("LemonldapUserShmSize");
	bless $self, $class;
	return $self
}

sub store {
	my ($self,%datas)=@_;
	print STDERR "Store new user ".$datas{uid}."\n" if(DEBUG);
	my $tmp = $datas{uid}."#"
			.$self->{config}->get_regexp_user($datas{groups})."#"
			.$self->{config}->header_spec(%datas)."#"
			.$datas{uid};
	$SHARE{$datas{id}}=$tmp;
	print STDERR $SHARE{$datas{id}}."\n" if(DEBUG);
}

sub get {
	# Return order: ($id,$uid,$urlReg,$headers,$trace)
	my ($self,$id)=@_;
	my $s=$SHARE{$id};
	return unless($s);
	my @t=split /#/, $s;
	$s=$t[1];
	$t[1] = qr/$s/;
	my %h=split /;/, $t[2];
	$t[2] = \%h;
	return ($id,@t);
}

sub cleanup {
	my $self=shift;
	# The cleanup is brutal, but later, we'll use a better one
	$self->{share}->clear if($self->{share}->size > $self->{max_size} * 0.95);
}
1;
