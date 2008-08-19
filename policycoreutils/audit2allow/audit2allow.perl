#!/usr/bin/perl

#    Adapted from:
#    newrules.pl, Copyright (C) 2001 Justin R. Smith (jsmith@mcs.drexel.edu)
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License as
#    published by the Free Software Foundation; either version 2 of
#    the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA     
#                                        02111-1307  USA
#    2003 Oct 11: Add -l option by Yuichi Nakamura(ynakam@users.sourceforge.jp)


$load_policy_pattern="avc:.*granted.*{.*load_policy.*}";

while ($opt = shift @ARGV) {
        if ($opt eq "-d") { $read_dmesg++; }
        elsif ($opt eq "-v") { $verbose++; }
        elsif ($opt eq "-i") { $input = shift @ARGV; }
        elsif ($opt eq "-o") { $output= shift @ARGV; }
	elsif ($opt eq "-l") { $load_policy++; }
	elsif ($opt eq "--help") { &printUsage; }
		else  { print "unknown option, '$opt'\n\n"; &printUsage; }
}

if ($read_dmesg && $input) {
	print "Error, can't read from both dmesg and $input\n\n";
	&printUsage;
}

if ($read_dmesg) { open (IN, "/bin/dmesg|"); } 
elsif ($input)   { open (IN, "$input");      }
else             { open (IN, "-");           }  # STDIN

if ($output)     { open (OUT, ">>$output");   }
else             { open (OUT, ">-");         }  # STDOUT

if($load_policy){ #store logs after last "load_policy" in @log_buf
    while ($line = <IN>) {
	if($line=~/$load_policy_pattern/) {
	     #stored logs are unnecessary
	     undef @log_buf;
	}
	else
	{
	    push @log_buf,$line;
	}
    }
}

while ($line=&readNewline) {
    next unless ($line =~ m/avc:\s*denied\s*\{((\w|\s)*)\}/);
    @types=split /\ /,$line;
    $info="";
    $group="";
    $command="";
    foreach $i(0..$#types){
	next if($types[$i]!~/[=\{]/);
       if($types[$i]=~/^\{/){
	    $j=$i+1;
	    while($types[$j]!~/\}/){
		$command.=" $types[$j]";
		$j++;
	    }
	    next;
	}
	my($a,$b) = split /=/,$types[$i];
	
	next if($a eq "pid");
	next if($a eq "dev");
	next if($a eq "ino");
	
	if(($a eq "scontext")||($a eq "tcontext")||($a eq "tclass")){
	    if($a ne "tclass"){
		my($c,$c,$c) = split /:/, $b;
		$b=$c;
	    }
	    $b=~s/\n//;
	    $group.="|$b";
	    next;
	}
	$b=~s/:\[\d+\]//;
	$a=uc $a;
	$info.="$a=$b  "; 
    }
    
    my($c,$c,$c,$c) = split /\|/, $group;
    $info=~s/\ $c=\S+\ //gi;
    # escape regexp patterns --<g>
    $info=~s/([^\w])/\\$1/g;
   
    @atypes=split /\ /,$command;
    foreach $i(0..$#atypes){
	$rules{$group}{$atypes[$i]}++;
    }
    
    $info.=" ";
    if($occur{$group}!~$info){
	$occur{$group}.="\t#$info: $command\n";
    }
    else{	
	my ($a,$b) = split /$info:\ /, $occur{$group};
	my ($temp) = split /\n/, $b;
	
	@com=split /\ /, $command;
	foreach $i(1..$#com){
	    $b=" $com[$i]$b" if($temp!~$com[$i]);
	}
	$occur{$group}="$a$info: $b";
    }
}

# done  with the input file
# now generate the rules
foreach $k (sort keys %rules)
{ 
    my ($a,$scontext,$tcontext,$tclass) = split /\|/, $k;
    if ($scontext eq $tcontext) {
        $tcontext = 'self';
    }
    print OUT  "allow $scontext $tcontext:$tclass";
    
    my $access_types = $rules{$k};
    $len=(keys %$access_types);
    if ($len gt 2 ) { print OUT  " {"; }
    foreach $t (sort keys %$access_types) {
      if ($t ne "") {print OUT  " $t";}
    }
    if ($len gt 2 ) { print OUT " }"; }
    print OUT ";\n";
    $occur{$k} =~ s/\\(.)/$1/g;  # de-escape string
    print OUT "$occur{$k}\n" if ($verbose);
}

exit;

sub readNewline {
    if($load_policy){
	$newline=shift @log_buf;
    }else{
	$newline=<IN>;
    }
    return $newline;
}

sub printUsage {
	print "audit2allow [-d] [-v] [-l] [-i <inputfile> ] [-o <outputfile>]
        -d      read input from output of /bin/dmesg
        -v      verbose output
        -l      read input only after last \"load_policy\"
        -i      read input from <inputfile>
        -o      append output to <outputfile>\n";
	exit;
}

