CREATE DATABASE `authlogin` /*!40100 DEFAULT CHARACTER SET latin1 */;

-- authlogin.userdata definition

CREATE TABLE `userdata` (
  `userId` int(11) NOT NULL AUTO_INCREMENT PRIMARY_KEY,
  `username` varchar(255) DEFAULT NULL,
  `tempPsw` varchar(255) DEFAULT NULL,
  `pswHash` varchar(255) DEFAULT NULL,
  `twoFAkey` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`userId`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=latin1;

-- Example users;

/*
// One user called "admin". Temp psw is set to "temp" which has to be changed when logged into the website with the following credentials.
// After a new password is set, the new password will be hashed and the temp password will be removed. 2fa can be setup after inside the website.

INSERT INTO userdata VALUES ('admin','temp', null, null);

*/