#include <stdio.h>                      /* stdio stuff */
#include <stdlib.h>                     /* free(), atoi() */
#include <unistd.h>                     /* sleep() */

#ifdef AGENT
#include "/opt/OV/include/opcapi.h"     /* ITO agent-side stuff */
#else
#include "/opt/OV/include/opcsvapi.h"   /* ITO server-side stuff */
#endif

#define ERRORMSGSIZE 1024
#define SLEEPEMPTY 1	/* sleep on empty input before new read attempt */
#define SLEEPOPEN 3	/* sleep between closing and reopening the input */

void error_msg(int code, char *text)
{
  int size;
  char *ptr;

  opcdata_get_error_msg(code, &ptr, &size);
  strncpy(text, ptr, size);
  text[size] = 0;
  free(ptr);
}



int open_if(char *ifname)
{
  int ret;
  char errortext[ERRORMSGSIZE];
  int interface;


#ifdef AGENT
  ret = opcif_open(OPCAGTIF_EXTMSGPROC_READWRITE, ifname, OPCIF_SV_RUNNING | 
    OPCIF_READ_NOWAIT | OPCIF_IGNORE_MSI_ALREADY_EXISTS, 0, &interface);
#else
  ret = opcif_open(OPCSVIF_EXTMSGPROC_READWRITE, ifname, OPCIF_SV_RUNNING | 
    OPCIF_READ_NOWAIT | OPCIF_IGNORE_MSI_ALREADY_EXISTS, 0, &interface);
#endif

  if (ret != OPC_ERR_OK) {

    error_msg(ret, errortext);

    fprintf(stderr, 
      "Error opening MSI interface \"%s\": %s\n", ifname, errortext);

    exit(1);
  }

  ret = opcif_register(interface, 0, 0);

  if (ret != OPC_ERR_OK) {

    error_msg(ret, errortext);

    fprintf(stderr, 
      "Error registering condition with MSI interface \"%s\": %s\n", 
        ifname, errortext);

    opcif_close(interface);

    exit(1);
  }

  return interface;
}



void find_sev(int severity, char *text)
{

  switch(severity) {

    case OPC_SEV_UNCHANGED:
      strcpy(text, "unchanged");
      break;

    case OPC_SEV_UNKNOWN:
      strcpy(text, "unknown");
      break;

    case OPC_SEV_NORMAL:
      strcpy(text, "normal");
      break;

    case OPC_SEV_WARNING:
      strcpy(text, "warning");
      break;

    case OPC_SEV_CRITICAL:
      strcpy(text, "critical");
      break;

    case OPC_SEV_MINOR:
      strcpy(text, "minor");
      break;

    case OPC_SEV_MAJOR:
      strcpy(text, "major");
      break;

  }

}



int main(int argc, char **argv)
{
  int interface;
  int reopen, sleepcounter;
  int ret;
  char errortext[ERRORMSGSIZE];
  opcdata msg;
  long time;
  long severity;
  char sevtext[32];
  char *id, *app, *obj, *node;
  char *msg_group, *msg_text;


  if (argc < 3) {

    fprintf(stderr, 
      "Usage: %s <MSI interface name> <reopen timeout>\n", argv[0]);
    exit(1);
  }

  /* set stdout buffering to line mode
     (needed if stdout was redirected to a file or to a pipe) */
  setvbuf(stdout, 0, _IOLBF, 0); 

  interface = open_if(argv[1]);
  reopen = atoi(argv[2]);

  opcdata_create(OPCDTYPE_EMPTY, &msg);

  sleepcounter = 0;

  for (;;) {

    ret = opcif_read(interface, msg);

    switch (ret) {

      case OPC_ERR_OK:

        sleepcounter = 0;

        id = opcdata_get_str(msg, OPCDATA_MSGID);
        time = opcdata_get_long(msg, OPCDATA_CREATION_TIME);
        severity = opcdata_get_long(msg, OPCDATA_SEVERITY);
        node = opcdata_get_str(msg, OPCDATA_NODENAME);
        app = opcdata_get_str(msg, OPCDATA_APPLICATION);
        obj = opcdata_get_str(msg, OPCDATA_OBJECT);
        msg_group = opcdata_get_str(msg, OPCDATA_GROUP);
        msg_text = opcdata_get_str(msg, OPCDATA_MSGTEXT);

	find_sev(severity, sevtext);

        printf("id=%s time=%ld sev=%s node=%s app=%s obj=%s msg_grp=%s msg_text=%s\n",
          id, time, sevtext, node, app, obj, msg_group, msg_text);

        break;

      case OPC_ERR_NO_DATA:

        sleep(SLEEPEMPTY);
        sleepcounter += SLEEPEMPTY;

        if (reopen  &&  sleepcounter >= reopen) {

          fprintf(stderr, "Reopening MSI interface \"%s\"\n", argv[1]);
          sleepcounter = 0;
          opcif_close(interface);
	  sleep(SLEEPOPEN);
          interface = open_if(argv[1]);
        }

        break;

      default:

        error_msg(ret, errortext);

        fprintf(stderr, "Error reading from MSI interface \"%s\": %s\n",
          argv[1], errortext);

        opcdata_free(&msg);
        opcif_close(interface);

        exit(1);

    }

  } 

}
 
use Getopt::Long;

# read options given in commandline

GetOptions( "conf=s" => \$conffile,
            "separator=s" => \$separator );


if (!defined($conffile)) {

print STDERR << "USAGE";

Usage: $0 -conf=<conffile> [-separator=<separator>]

USAGE

exit(1);

}


# Default regular expression that is used to detect field boundaries 
# in configuration file

if (!defined($separator))  { $separator = '\s+\|\s+'; }


##############################
# Functions
##############################

sub log_msg {

  my($msg) = $_[0];

  print STDERR "$msg\n";

}



sub convert_actionlist {

  my($actionlist) = $_[0];
  my(@parts, $action, $result);
  my($context, $lifetime);

  @parts = split(/\s*;\s*/, $actionlist);
  $result = "";
  
  foreach $action (@parts) {

    if ($action =~ /^create\s*(\d*)\s*(.*)/i) {
 
      $lifetime = $1;
      $context = $2;

      if (!length($context)) { $context = "%s"; }

      $result .= "create " . $context . " " . $lifetime . "; ";
 
    } else {

      $result .= $action . "; ";

    }

  }

  return $result;

}



sub convert_config {

  my($line, $i, $cont, @comp, $type);


  log_msg("Reading configuration from $conffile...");

  if (open(CONFFILE, "$conffile")) {

    $i = 0;
    $cont = 0;

    while (<CONFFILE>) {

      # check if current line belongs to previous line;
      # if it does, form a single line from them
 
      if ($cont)  { $line .= $_; }  else { $line = $_; }

      # remove whitespaces from line beginnings and ends;
      # if line is empty or all-whitespace, print empty line,
      # take next line, and set $cont to 0

      if ($line =~ /^\s*(.*\S)/) { $line = $1; }  
        else { print "\n"; $cont = 0; next; }

      # check if line ends with '\\'; if it does, remove '\\', set $cont
      # to 1 and jump at the start of loop to read next line, otherwise 
      # set $cont to 0

      if (rindex($line, '\\') == length($line) - 1) { 

        chop($line);
        $cont = 1;
        next;

      } else { $cont = 0; }

      # preserve comment lines

      if (index($line, '#') == 0) { 

        print $line, "\n";
        next; 

      }

      # split line into fields

      @comp = split(/$separator/, $line);

      # find the rule type

      $type = uc($comp[0]);

      # ------------------------------------------------------------
      # SINGLE rule
      # ------------------------------------------------------------

      if ($type eq "SINGLE") {

        if (scalar(@comp) < 6  ||  scalar(@comp) > 7) { 

          log_msg("Wrong number of parameters specified at line $.");
          next; 

        }

        $comp[5] = convert_actionlist($comp[5]);

        print "type=Single\n";
        print "continue=$comp[1]\n";
        print "ptype=$comp[2]\n";
        print "pattern=$comp[3]\n";
 
        if (defined($comp[6])) { print "context=$comp[6]\n"; }

        print "desc=$comp[4]\n";
        print "action=$comp[5]\n";

        ++$i;

      }


      # ------------------------------------------------------------
      # SINGLE_W_SCRIPT rule
      # ------------------------------------------------------------

      elsif ($type eq "SINGLEWITHSCRIPT") {

        if (scalar(@comp) < 7  ||  scalar(@comp) > 8) { 

          log_msg("Wrong number of parameters specified at line $.");
          next; 

        }

        $comp[6] = convert_actionlist($comp[6]);

        print "type=SingleWithScript\n";
        print "continue=$comp[1]\n";
        print "ptype=$comp[2]\n";
        print "pattern=$comp[3]\n";

        if (defined($comp[7])) { print "context=$comp[7]\n"; }

        print "script=$comp[4]\n";
        print "desc=$comp[5]\n";
        print "action=$comp[6]\n";

        ++$i;

      }


      # ------------------------------------------------------------
      # SINGLE_W_SUPPRESS rule
      # ------------------------------------------------------------

      elsif ($type eq "SINGLEWITHSUPPRESS") {

        if (scalar(@comp) < 7  ||  scalar(@comp) > 8) { 

          log_msg("Wrong number of parameters specified at line $.");
          next; 

        }

        $comp[5] = convert_actionlist($comp[5]);

        print "type=SingleWithSuppress\n";
        print "continue=$comp[1]\n";
        print "ptype=$comp[2]\n";
        print "pattern=$comp[3]\n";

        if (defined($comp[7])) { print "context=$comp[7]\n"; }

        print "desc=$comp[4]\n";
        print "action=$comp[5]\n";
        print "window=$comp[6]\n";

	++$i;

      }


      # ------------------------------------------------------------
      # PAIR rule
      # ------------------------------------------------------------

      elsif ($type eq "PAIR") {

        if (scalar(@comp) < 11  ||  scalar(@comp) > 12) { 

          log_msg("Wrong number of parameters specified at line $.");
          next; 

        }

        $comp[5] = convert_actionlist($comp[5]);
        $comp[9] = convert_actionlist($comp[9]);

        print "type=Pair\n";
        print "continue=$comp[1]\n";
        print "ptype=$comp[2]\n";
        print "pattern=$comp[3]\n";

        if (defined($comp[11])) {
 
          print "context=$comp[11]\n";
 
        }

        print "desc=$comp[4]\n";
        print "action=$comp[5]\n";

        print "continue2=$comp[1]\n";
        print "ptype2=$comp[6]\n";
        print "pattern2=$comp[7]\n";

        if (defined($comp[11])) {
 
          $comp[11] =~ s/\$(\d+)/%$1/g;
          print "context2=$comp[11]\n";
 
        }

        print "desc2=$comp[8]\n";
        print "action2=$comp[9]\n";
        print "window=$comp[10]\n";

	++$i;

      }
  

      # ------------------------------------------------------------
      # PAIR_W_WINDOW rule
      # ------------------------------------------------------------

      elsif ($type eq "PAIRWITHWINDOW") {

        if (scalar(@comp) < 11  ||  scalar(@comp) > 12) { 

          log_msg("Wrong number of parameters specified at line $.");
          next; 

        }

        $comp[5] = convert_actionlist($comp[5]);
        $comp[9] = convert_actionlist($comp[9]);

        print "type=PairWithWindow\n";
        print "continue=$comp[1]\n";
        print "ptype=$comp[2]\n";
        print "pattern=$comp[3]\n";

        if (defined($comp[11])) {
 
          print "context=$comp[11]\n";
 
        }

        print "desc=$comp[4]\n";
        print "action=$comp[5]\n";

        print "continue2=$comp[1]\n";
        print "ptype2=$comp[6]\n";
        print "pattern2=$comp[7]\n";

        if (defined($comp[11])) {
 
          $comp[11] =~ s/\$(\d+)/%$1/g;
          print "context2=$comp[11]\n";
 
        }

        print "desc2=$comp[8]\n";
        print "action2=$comp[9]\n";
        print "window=$comp[10]\n";

	++$i;

      }
 

      # ------------------------------------------------------------
      # SINGLE_W_THRESHOLD rule
      # ------------------------------------------------------------

      elsif ($type eq "SINGLEWITHTHRESHOLD") {

        if (scalar(@comp) < 8  ||  scalar(@comp) > 9) { 

          log_msg("Wrong number of parameters specified at line $.");
          next; 

        }

        $comp[5] = convert_actionlist($comp[5]);

        print "type=SingleWithThreshold\n";
        print "continue=$comp[1]\n";
        print "ptype=$comp[2]\n";
        print "pattern=$comp[3]\n";

        if (defined($comp[8])) { print "context=$comp[8]\n"; }

        print "desc=$comp[4]\n";
        print "action=$comp[5]\n";
        print "window=$comp[6]\n";
        print "thresh=$comp[7]\n";

	++$i;

      }


      # ------------------------------------------------------------
      # SINGLE_W_2_THRESHOLDS rule
      # ------------------------------------------------------------

      elsif ($type eq "SINGLEWITH2THRESHOLDS") {

        if (scalar(@comp) < 12  ||  scalar(@comp) > 13) { 

          log_msg("Wrong number of parameters specified at line $.");
          next; 

        }

        $comp[5] = convert_actionlist($comp[5]);
        $comp[9] = convert_actionlist($comp[9]);

        print "type=SingleWith2Thresholds\n";
        print "continue=$comp[1]\n";
        print "ptype=$comp[2]\n";
        print "pattern=$comp[3]\n";

        if (defined($comp[12])) { print "context=$comp[12]\n"; }

        print "desc=$comp[4]\n";
        print "action=$comp[5]\n";
        print "window=$comp[6]\n";
        print "thresh=$comp[7]\n";
        print "desc2=$comp[8]\n";
        print "action2=$comp[9]\n";
        print "window2=$comp[10]\n";
        print "thresh2=$comp[11]\n";

	++$i;

      }


      # ------------------------------------------------------------
      # SUPPRESS rule
      # ------------------------------------------------------------

      elsif ($type eq "SUPPRESS") {

        if (scalar(@comp) < 3  ||  scalar(@comp) > 4) { 

          log_msg("Wrong number of parameters specified at line $.");
          next; 

        }

        print "type=Suppress\n";
        print "ptype=$comp[1]\n";
        print "pattern=$comp[2]\n";

        if (defined($comp[3])) { print "context=$comp[3]\n"; }

	++$i;

      }


      # ------------------------------------------------------------
      # CALENDAR rule
      # ------------------------------------------------------------

      elsif ($type eq "CALENDAR") {

        if (scalar(@comp) < 4  ||  scalar(@comp) > 5) { 

          log_msg("Wrong number of parameters specified at line $.");
          next; 

        }

        $comp[3] = convert_actionlist($comp[3]);

        print "type=Calendar\n";
        print "time=$comp[1]\n";

        if (defined($comp[4])) { print "context=$comp[4]\n"; }

        print "desc=$comp[2]\n";
        print "action=$comp[3]\n";

	++$i;

      }

      # ------------------------------------------------------------
      # unknown rule
      # ------------------------------------------------------------
      
      else { log_msg("Unknown rule type '$type' specified at line $."); }

      print "\n";

    }

    close CONFFILE;

    log_msg("$i rules converted");

  } else {

    log_msg("Can't open configuration file $conffile, exiting");

  }

}

convert_config();
