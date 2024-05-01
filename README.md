# A-Student-Portal

# Author: Hamdy Ousama Hamdy (Hamdy410)

# Project Description
## Overview
This project has been dedicated as the final project for the famous Computer Science course: __*CS50x: Introduction to Computer Science*__.

This student portal is a web-based project that aims to facilitate the communication between students, faculty staff members and the system admins. By integrating HTML, CSS and Javascript as a front-end and python with its Flask frameword for the back-end.

## Features
1. __Admin Pages__:
   * Registeration of new students
   * Regulating the *Media Section* and allows adding or deleting posts
   * Send alerts to all users. However, recieve alerts only from other members

2. __Master Admin Control Unit Pages__:
   * Registration of new admins as well as new faculty staff members
   * Assign courses and add them to faculty staff
   * Send alerts to all users at once
   * Suspend users as per required from logging into the web-application

3. __Faculty Staff__:
   * View the details of their assigned courses
   * Access to the Media section where they can post or reply to each other posts
   * Send alerts to each other and to students, but not to admins. However, they can recieve alerts from admins.

4. __Students__:
   * The ability to enroll to courses compatible with their own year and semester or study.
   * Access to the Media Section, where they can post and reply to other posts
   * Receive alerts from both admins and faculty staff members

# Installation:
## Software requirements
1. __Python__:
   * Ensure you have __Python__ installed on your system (version 3.x recommended)
   * Python is used to completely handle the back-end operations of the web-app.
   * Users can run the Python scripts found (_encrypt.py_) to insert the first master Admin into the website.
   * Users can initiate the Flask server– and only for developing purposes– using the (_app.py_) file. Note that the third python script (_helper.py_) is a custom library that is built to aid the operations of (_app.py_)

     Note: There will be more explaination regarding the last three points in the following section. Specifically, the Code Documentation section later on.

  ### Python libraries needed:
    - The CS50 third-party library (SQL regulations)
    - Flask library used (regulated the app requests and main operation, considered that Flask is a the framework used for the website)
    - Flask-Session used (Online sessions regulations)
    - sendgrid library (sendgrid API regulations)
    - Werkzeug library (security measures and password checking)

    Each of the libraries can be installed using the following commands:
    ```
    pip install cs50
    pip install Flask
    pip install Flask-Session
    pip install sendgrid
    pip install Werkzeug
    ```

    Make sure you have `pip` installed on your system before running these commands. If you are using a virtual environment (which is recommended for Python projects), activate it before installing the packages. Additionaly, you may need to use `pip3` instead of `pip` if you're working with Python 3.x.

    If you encounter any issues with permissions, you might need to add `--user` to install the packages locally for your user, or use `sudo` for a system-wide installation, though the latter is generally not recommended for security reasons. Always ensure you're installing the correct version of the library that's compatible with your project's Python version.

2. __Integrated Development Environment (IDE)__:
   In my development, I prefered using Visual Studio Code (VS Code), however, any text editor program that you would be comfortable with would be suitable for editing the Python Scripts (Which we will discuss in the following section)

# Usage
You would be required to follow the following steps to ensure that the webapp would function properly.

## Generate an API Key
   It is a must to general your own sendGrid API Key, which would facilitate automated emails to be sent to your users in the future. In general SendGrid is an Email API and helps offers other tools that you might helpful. For this project, please follow the steps.

   * Enter the website of *sendgrid* using the following link:
      [InternetShortcut](URL=https://sendgrid.com/en-us)

   * Sign up using a new account if you don't have one.
   * Request an API generation after filling the required details
   * Store the API Key into an environment variable on your device and that would be through using the commands:
    - For Windows:
     ```
     set SENDGRID_API_KEY="#Your Key"
     ```
    - For Linux:
    ```
    export SENDGRID_API_KEY="#Your Key"
    ```
    However, this would last for only your current session. If you want to set it permenently, you can add the export command to your shell's startup file, like `.bashrc` or `.bash_profile`

  * Store the used email _the sender email_ into an environment variable as well using the same method. However, it should be named as __SOURCE_EMAIL__
  * Store a variable of a string for your Master Admin Control Unit access. This is recommended to be as hard as possible for users even for the Master admin to memorize since it can control the major high-authority operations on the page. This password would be following the name __ADMIN_PASSWORD__

## Insert the Head Developer (Master Admin)
You would be required to change the current data inside a python script file called _(encrypt.py)_. The main aim of this file would be to assign the first admin (and Master Admin) at the same time to have accessability over the webapp. You would find comments or space holders in the file that would facilitate the assign. It's recommended not to use the file in inserting new users as that would affect the security of the app, so the file would delete itself after finishing its operation.

  * Change the variables in the the file as that written at the beginning of the file.
  * Run the command:
    ```
    python encrypt.py
    ```
  * If the program operated correctly, The file itself would have been deleted by now.

## Run your server

1. __As a developer__:
   This web application supports the Flask framework, so if and only if, you want to further develop your application before the commercial launch you would be required to run the command
   ```
   flask run
   ```
in the main directory where the file _(app.py)_ is found.

2. __For commercial purposes__:
   In this case it would be required for your IT department to handle assigning the server code to successfully align it with the server security regulations.

## Adjusting your web environment.
In order to be completely ready for your web application to be fully functional, open the website using the domain assigned to it whether it has been launched commercially or for developing.

### Log in
Since you have assigned the first user (the Master Admin, or in general the first admin), you should enter you log in page. There you would write the user_id (username)– A1 for the first user– and click on the admins identity radio.

This will redirect you to another webpage with a form. Fill the form with required information and ensure that your email is working.

You would be redirected to a webpage that requests your received OTP, consisting of 6 characters of alphanumerals, you should insert each character in a separate unit of its own.

Note that:
  * The required National ID must be the same as the one written in the encrypt.py file.
  * The email received might be sent to your spam so it's recommended to check you junk and spam contents.
  * You have three OTP attempts, otherwise you would be redirected to the Apology page. You then can try to log in later or using a different OTP.

### Get to the Master Admin Control Unit first
Through changing your domain route to __admin/password__ route where you would be sent to a secret page that requires a password. This is the same password that you have set for your environment under the environment variable named as __ADMIN_PASSWORD__. If written correctly, you would be sent to the Master Admin Control Unit.

There you can– as explained in the features section earlier –register new users like faculty staff and other user members. You would simply use the navigation bar on your far left named as _New Users_, there you would find a form.

### Insert Admins and Faculty staff memebers
An arrow would be found pointing at a switch of form to allow switching between the __*Faculty Staff*__ users and __*Admins*__ users. You would be required to insert each user simultaneously following specific measures, like: "two same National IDs could not be inserted at the same time", "birthdays must be logical".

### Assign courses to Faculty Staff
In another page, which could be accessed through the nav bar on the left, you can start inserting details about courses of the year, and their details. Also, you can delete courses if inserted incorrectly, or no longer of validity.

### Optional features as a Master Admin:
  * You might need to sometimes suspend users from entering the web application. Whether for security reasons or because they have left the system. Sensitive information is encrypted in your database anyways, so it might not be of a problem to have the data of previous users. If necessary, for storage and data options, you might prefer to free some of your older members. However, the web application doesn't currently support deleting users.
  * Sending alerts to all users at once. In this section, you can send all users alerting messages at the same time regarding a specific regulation or maybe you would like to greet them on new years😅. If you wanted to send an alert for all users regarding a major development or so, it will be a useful feature to quickly communicate with your environment users.

__*From here, you can now send the user Ids to your users by your prefered means. Following the same standard log in instructions is the correct way to admins, faculty staff, and students page*__

### Registering new Students as an Admin
Each new year or semester you can start inserting the required information for new students as users on the web application. This would be only through the _Admins pages_ (the Master Admin themselves have their own natural admins pages). Through navigating to the __New Students__ section, you would be redirected to a form with the required info about the student.

# Documentation for developers
## At the beginning of the *app.py* file
You would find some configurations that you might be interested in changing in case you would like to adjust the project to your own requirments.

1. __From line 21 – 24__:
   It is configured that a single session for a user would be stored in the _filesystem_ type, with a constant duration of 15 minutes from the time the user would log in to the system

2. __From line 27 – 32__:
   It is used to initiate the sendgrid API configuration for automated email to be sent to users, as for their first registration OTP.
   It is written according the SendGrid API offcial documentation found at: [Uploading SendGrid Documentation - Twilio.url…](URL=https://docs.sendgrid.com/)

3. __line 35__:
   Adjust the url toward the database, as for what's found using the CS50 library documentation.
[Uploading CS50 Library for Python — CS50 Docs.url…](URL=https://cs50.readthedocs.io/libraries/cs50/python/)

4. __From line 38 – 91__:
   These are the adjusted constants for the web application which are used for verification purposes along the application's routes.
   * There is a variable called MASTER_ADMIN_CONTROL_UNIT_PASSWORD. This specific variable is extremely important in regulating the access password to the Master Admin Control Unit.

5. __From line 102 – 333__:
   They regulate three routes _login_, _register_, and _otp_ routes which regulate the first steps of the experience of any user. They contain comments and explanations upon their usages and the purpose of some lines or groups of lines.

7. __From line 336 – 821__:
   Regulates all the routes required to configure the master admin control unit and ensure its functionalities.

8. __From line 824 – 963__:
   Regulates the routes required to ensure the functionality of the admins' pages

9. __From line 966 – 1004__:
   Regulates the routes required to ensure the functionality of the faculty staff members' pages.

10. __From line 1007 – 1133__:
    Regulates the routes required to ensure the functionality of the students' pages.

11. __From line 1136 – 1542__:
    Has the entire additional routes which are not special for a specific user. They are being regulated among all users equally.

__*In each of these groups, you would find comments that throroughly explains the lines and their purposes*__

# Personal practices
1. HTTP request methods have been used like __PATCH, POST, and GET__.
2. The seperated routes could have been used seperately for their identitfied routes, however, I prefered to have them seperated to make the additional features be all at the end of the file. It might be clearer and more readable for further development and improvement. This was the matter of personal cause and could be manipulated if preferred.
3. JSON was used in the HTML pages with addition to Mutation Observers to enhance the security measures of the pages instead of only using the built-in form methods and actions. Providing two levels of security (on the client-side and on the server-side) was something I personally saw as extremely beneficial.
4. If you looked through the syntax carefully, you would find out that some routes are distinctive to their own users' identities. Routes like _"/students/alerts"_ is already prepared (or could be adjusted) at the route _"/alerts"_. However, because of some HTML adjustments, they had their own routes.
5. Older members were preferable to not be completely deleted from the system. Some future security regulations might be important for specific organizations and that would be according to their own preferences.
6. For new users, it would be cumbersome trying to regulate and adjust the user with their corresponding User ID. Because such information is sensitive and might be changeable between organizations, I personally believed that giving the developers their own opportunity in regulating this process. However, there is more discussed in the future development section.

# For further development
1. The __Websocket__ protocol is beneficial in accurately and regulatory push new data from the server to the client-side. This could enhance the experience of alerts, replies and posts in the system.
2. __Repetitions__ in the _app.py_ file should be enhanced to make the web app code more concise. The checking of users according their identities or the insertion of alerts between two routes (as explained earlier) must allow higher readability for the future
3. __Jvascript__: Some HTML pages share the same JS code. Searching on the internet, performance might be enhanced if we could add the JS code in separate files that could be cached for later use. Also, allowing different pages to share the same file will also enhance performance.
4. __Jinja2__: After working for some time on the project, I found out that we could extend HTML files (using DJANGO and Jinja2) multiple times. Therefore, having the main layout of the page, different nav bars for each identity, and decreasing the number of conditions of one pages might also improve performance.
5. __Database__: I have tried to develop a concise database. The current one handles most cases, however, I find it harder to find the right compatible combination of compactibility and performance in dealing with the fairly limited environment of using sqlite3.
6. __HTML styling__: There is a small issue when the components of the website is smaller than the actual width of the web browser causing an empty space with only the color of the background.

# Acknowledgements

At the end, I would like to send my special thanks to the CS50 staff members who have guided us through this journey. At the beginning of this online course, I had no former idea what programming might be, but their quality, and friendly environment was the point from where my programming journey started.

Special thanks to __*Professor David J.Malan*__ for his endeavor to teach aspiring computer scientists and inspriring them.

I would also like to send thanks to my friend who aided in the color palettes of this website. Your acknowledgements are saved no worries😁. I am still confused between the shades of white. They all look white 🎨😄.
  
