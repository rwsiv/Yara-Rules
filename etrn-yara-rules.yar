/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

/*
  Description: Detect spam with IP URLs and long <style> section
  Priority: 5
  Scope: Against Email
  Tags: None
  Created by ETRN.com on 2018/01/25
*/

rule Email_SPAM_IP_URL_LongStyle_1516938607
{
  meta:
		Author = "https://etrn.com/"
		reference = "https://github.com/phishme/malware_analysis/blob/master/yara_rules/cryptowall.yar"
  strings:
    /*
      http://151.106.7.30//click.php?
      http://204.12.247.218/uc.php?
      http://31.192.240.88/click.html?
    */
    $url1 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\/\w+\.php\?/
    $url2 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\w+=/
    $url3 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\w+\.html\?/
    $url4 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\w+\.php\?/

    $style1 = "<style>"
    $style3 = /[[:punct:]]{84}\w+[[:punct:]]{84}/

  condition:
    1 of ($url*) and 2 of ($style*) and filesize > 500KB
}

/*
  Matches a long list of broken <img tags (often inside a <style> section)
*/
rule Email_SPAM_IP_URL_LongStyle_1523037727
{
  meta:
                Author = "https://etrn.com/"
                reference = "https://github.com/phishme/malware_analysis/blob/master/yara_rules/cryptowall.yar"
  strings:
    /*
      http://151.106.7.30//click.php?
      http://204.12.247.218/uc.php?
      http://31.192.240.88/click.html?
    */
    $url1 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\/\w+\.php\?/
    $url2 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\w+=/
    $url3 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\w+\.html\?/
    $url4 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\w+\.php\?/

    $style1 = "<style>"
    $style3 = /(?:<img class=[^>]+?){10}/

  condition:
    1 of ($url*) and 2 of ($style*) and filesize > 500KB
}

rule Email_SPAM_IP_URL_LongScript_1518804881
{
  meta:
                Author = "https://etrn.com/"
                reference = "https://github.com/phishme/malware_analysis/blob/master/yara_rules/cryptowall.yar"
  strings:
    /*
      http://151.106.7.30//click.php?
    */
    $url1 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\/\w+\.(html|php)\?/
    $url2 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\w+=/
    $url3 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\w+\.(html|php)\?/

    $script1 = "<script>"
    /* $script2 = /\w{8}-\w{4}-\w{4}-\w{4}-/ */
    $script3 = /[[:punct:]]{84}\w+[[:punct:]]{84}/

  condition:
    1 of ($url*) and 2 of ($script*) and filesize > 200KB
}

rule Email_SPAM_IP_URL_LongScript_MAP_1518805374
{
  meta:
		Author = "https://etrn.com/"
		reference = "https://github.com/phishme/malware_analysis/blob/master/yara_rules/cryptowall.yar"

  strings:
    /*
      http://151.106.7.30//click.php?
      http://151.106.7.30/Zy0=
      http://85.204.49.81/lnk.php?
    */
    $url1 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\/\w+\.(html|php)\?/
    $url2 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\w+=/
    $url3 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\w+\.(html|php)\?/

    // $script1 = "<script>" nocase
    // $script2 = "</script>" nocase
    // $script3 = /<script>.{1,32700}?<\/script>/
    // $script4 = /<script>.{32700,}?/
    // $script5 = /.{32700,}?<\/script>/
    $script1 = /<script>[\t\n\r\f.]{,32}?<MAP .+?>http(s)?:\/\/(\w+\.)+\w+\/(.+?)<\/MAP>/
    $script2 = /<MAP .+?>http(s)?:\/\/(\w+\.)+\w+\/(.+?)<\/MAP>[\t\n\r\f.]{,32}?<\/script>/
    // $map = /<MAP .+?>http(s)?:\/\/(\w+\.)+\w+\/.+<\/MAP>/

  condition:
    // 1 of ($url*) and $script1 and $script2 and not $script3 and $script4 and $script5 and $map and filesize > 200KB
    1 of ($url*) and $script1 and $script2 and filesize > 200KB

}

rule Email_SPAM_HTML_LongScript_var_1522080221
{
  meta:
		Author = "https://etrn.com/"

  strings:
    $script1 = "<script>" nocase
    $script2 = "</script>" nocase
    // $script3 = /var\s+\w+=\[/
    $script4 = /(?:\\x[0-9a-f]{2}){1100}/

  condition:
    all of ($script*) and filesize > 64KB
    // $script4 and filesize > 64KB
}

/*
  Description: Detect spam with WP URLs and call to download an encrypted file
  Priority: 5
  Scope: Against Email
  Tags: None
  Created by ETRN.com on 2018/03/26
*/

rule Email_SPAM_WP_URI_ShareFile_1522099609
{
  meta:
                Author = "https://etrn.com/"

  strings:
    $uri1 = "/wp-content/themes/"
    $uri2 = "/wp-admin/"
    $uri3 = /\/wp-content\/(?:plugins|uploads|themes)\/\w+\.php\b/
    $uri4 = /\/wp-includes\/\w+\.php\b/
    $uri5 = /\/images\/\w+\.(?:asp|php)\?/
    $text1 = "has sent you an encrypted message."
    $text2 = "access the file using your email credentials."
    $text3 = "ShareFile Encrypted Email Service"
    $text4 = "View Encrypted Message<https"

  condition:
    1 of ($uri*) and 1 of ($text*)
}

/*
  Description: Detect spam with American Express like phishing content
  Priority: 5
  Scope: Against Email
  Tags: None
  Created by ETRN.com on 2018/03/28
*/

rule Email_Phish_Aexp_1522229129
{
  meta:
		Author = "https://etrn.com/"

  strings:
    $text1 = "We are writing to let you know that there is a recent security report for your American Express(R) Account(s)" nocase
    $text2 = "At time of report diligency, We ran into problem validating your profile." nocase
    $text3 = "In view of this, Cardmember information needs to be updated and your mandatory effort is required." nocase
    $text4 = "See Attached Information Form, Download and Open to Continue." nocase
    $text5 = "Finish steps by filling out the Form." nocase

  condition:
    all of ($text*)
}

/*
  Description: Detect spam with common patterns
  Priority: 5
  Scope: Against Email
  Tags: None
  Created by ETRN.com on 2018/04/06
*/
/*
rule Email_Spam_click_1523036691
{
  meta:
		Author = "https://etrn.com/"

  strings:
    //$link1 = m'http://31.192.240.88/click.html\?'
    $link1 = /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/click\.html\?/

  condition:
    any of ($link*)
}
*/
