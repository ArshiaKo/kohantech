<?php

$recipient = "torahtimes613@gmail.com";  // Please insert your email address (between the quotation marks)

$yourname = "ShabbatTimes";  // Please insert your name here (between the quotation marks) It will appear as the sender in the thank-you mail.

$cfg['DATA_PRIVACY_POLICY'] = 0;  //  0 = Without data privacy policy   1 = With data privacy policy

$dataprivacypolicy = "data-protection.php";  //  Path to data privacy notice. You can replace "data-protection.php" with a link or URL (must begin with "http://www.")
    
$thankyou = "thankyou.php";  // Path to thank-you page. You can replace "thankyou.php" with a link or URL. (must begin with "http://www.") You can also use this script to show the linked thank-you page outside the iFrame: https://www.kontaktformular.com/en/embed-form-script-php-contact-form.html#outsideiframe


    

// Spam protection - settings //

$cfg['Security_code'] = 0;  //  0 = Without security code   1 = With security code

$cfg['Security_question'] = 0;  //  0 = Without security question   1 = With security question

$cfg['Honeypot'] = 0;  //  0 = Without honeypot   1 = With honeypot 
	
$cfg['Time-out'] = 0;  //  Minimum number of seconds between displaying and sending the form	 0 = No time-out
	
$cfg['Click_check'] = 0;  //  0 = Without click check   1 = With click check

$cfg['Links'] = 0;  //  Number of maximum links allowed  (0 = no links allowed)
	
$cfg['Badwordfilter'] = 'sex%, pussy%, porn%, %.ru, %.ru/%, %cos%, %gender%';  // Words for bad word filter 0 or empty = No bad word filter

// How the bad word filter works:
// badword = matches when message includes the full word   
// badword% = matches when message includes the bad word AND when a word begins with the bad word   
// %badword = matches when message includes the bad word AND when a word ends with the bad word    
// %badword% = matches when message includes the bad word AND when a word contains the bad word
	
$cfg['Badwordfields'] = 'title, first_name, name, company, telephone, email, subject, message';  //   Names of fields to be checked with the bad word filter - case sensitive!
	



// Other settings //

$cfg['Send_copy'] = 0;    //  0 = Never send a copy   1 = Ask user before sending copy   2 = Always send a copy (without asking)

$cfg['HTML5_error_messages'] = 1;  //  0 = Without HTML5 error messages   1 = With HTML5 error messages

$cfg['Show_icons'] = 1;  //  0 = Without Icons    1 = With Icons	


// You can activate the SMTP function in the next step. Important: You must have installed at least PHP 7.0 or higher on your web server! Open phpinfo.php in your browser to check your current PHP version. //

$smtp = array();

$smtp['enabled'] = 1; // Do you want the contact form to send emails via an SMTP server?   Yes = 1   No = 0

$smtp['host'] = 'smtp.gmail.com'; // SMTP server host (e.g. smtp.gmail.com)
   
$smtp['user'] = 'TorahTimes613@gmail.com'; // User name to authenticate yourself on the SMTP server (could be the aforementioned email address!)

$smtp['password'] = 'jqbebikrkiyvwbvv'; // Password to authenticate yourself on the SMTP server.

$smtp['encryption'] = 'ssl'; // Type of encryption used when connected to your SMTP server: '', 'ssl' or 'tls'

$smtp['port'] = 465; // TCP port, at which your SMTP server can be reached.

$smtp['debug'] = 0; // Debug level (0 - 4)
      
    
    
    
// You can activate the upload function in the next step.

$cfg['NUM_ATTACHMENT_FIELDS'] = 0;	// Number of attachment fields

$cfg['UPLOAD_ACTIVE'] = 1;		// 1 = Attachments are sent as email attachments (standard) 2 = Attachments are uploaded to a directory (please complete the information below)

$cfg['WHITELIST_EXT'] = 'pdf|png|jpg';	// Allowed file extensions - for example: pdf|png|jpg

$cfg['MAX_FILE_SIZE'] = 1024;		// Maximum file size of one file in KB. (This option depends on the PHP and server settings.)

$cfg['MAX_ATTACHMENT_SIZE'] = 2048;	// Maximum file size of several files in KB. (if more than 1 upload field)

$cfg['BLACKLIST_IP'] = array('12.345.67.89');	// Blocked IPs - for example: array('192.168.1.2', '192.168.2.4');


// If you want to upload the attachments to a directory, please complete this information

$cfg['UPLOAD_FOLDER'] = 'upload';	// You must create an "upload" folder. This requires write permissions. (chmod 777)

$cfg['DOWNLOAD_URL'] = 'https://www.website.com/contactform';	// Path to the form (without / at the end)




// Define maximum number of characters per field //

$number_of_characters_company = "50";  // Maximum number of characters for field "Company" (between the quotation marks)

$number_of_characters_first_name = "50"; // Maximum number of characters for field "First Name" (between the quotation marks)

$number_of_characters_name = "50"; // Maximum number of characters for field "Last Name" (between the quotation marks)

$number_of_characters_email = "50"; // Maximum number of characters for field "Email" (between the quotation marks)

$number_of_characters_telephone = "50"; // Maximum number of characters for field "Telephone" (between the quotation marks)

$number_of_characters_subject = "50"; // Maximum number of characters for field "Subject" (between the quotation marks)

?> 