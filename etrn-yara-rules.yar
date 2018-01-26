/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
  Description: Detect spam with IP URLs and long <style> section
  Priority: 5
  Scope: Against Email
  Tags: None
  Created by ETRN.com on 2018/01/25
*/

rule Email_SPAM_IP_URL_LongStyle_1516938607 : mail
{
  meta:
		Author = "https://etrn.com/"
		reference = "https://github.com/phishme/malware_analysis/blob/master/yara_rules/cryptowall.yar"
  strings:
    /*
      http://151.106.7.30//click.php?
    */
    $url1 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\/\w+\.php\?/
    $url2 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\w+=/

    $style1 = "<style>"
    $style3 = /[[:punct:]]{84}\w+[[:punct:]]{84}/

  condition:
    1 of ($url*) and 2 of ($style*) and filesize > 500000
}

rule Email_SPAM_IP_URL_LongScript_1516941763 : mail
{
  meta:
                Author = "https://etrn.com/"
                reference = "https://github.com/phishme/malware_analysis/blob/master/yara_rules/cryptowall.yar"
  strings:
    /*
      http://151.106.7.30//click.php?
    */
    $url1 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\/\w+\.php\?/
    $url2 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\w+=/

    $script1 = "<script>"
    $script2 = /\w{8}-\w{4}-\w{4}-\w{4}-/

  condition:
    1 of ($url*) and 2 of ($script*) and filesize > 200000
}
