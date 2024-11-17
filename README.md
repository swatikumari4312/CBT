<img align="right" src="https://visitor-badge.laobi.icu/badge?page_id=salesp07.MyMind">

# BBY-31 -> MyMind
<img src="https://raw.githubusercontent.com/salesp07/salesp07.github.io/master/public/mymind-responsive.png" alt="MyMind screenshot"/>

## Contributors
Towa Quimbayo:
[LinkedIn](https://www.linkedin.com/in/towa-quimbayo/) |
[GitHub](https://github.com/towaquimbayo)

Kian Azizkhani
[LinkedIn](https://www.linkedin.com/in/kian-azizkhani/) |
[GitHub](https://github.com/KianAzizkhani)

Pedro Sales-Muniz
[LinkedIn](https://www.linkedin.com/in/pedro-sales-muniz/) |
[GitHub](https://github.com/salesp07)

Alex Gibbison
[LinkedIn](https://www.linkedin.com/in/alexander-gibbison-786683153/) |
[GitHub](https://github.com/Soultey )

<img src="https://contrib.rocks/image?repo=salesp07/MyMind" />

Milestone 1: Login / Logout - 100% Completed\
Milestone 2: Patient, Therapist, and Admin user types - 100% Completed\
Milestone 3: Admin Dashboard - 100% Completed\
Milestone 4: Shopping Cart Component - 100% Completed\
Milestone 5: Online Chat - 100% Completed

## One sentence pitch
Our team BBY31\
is developing MyMind which is a web application\
to help people struggling with mental health problems\
to provide professional help from our therapist specialist that can help improve their mental health\
with guided therapy sessions.

## Technologies used
Frontend - HTML, CSS\
Backend - Node.js, JavaScript, jQuery, Ajax,  MongoDB Altlas,  Git, Heroku 
Node.js Modules - Nodemon, Express.js, Express-session, Path, Mongoose, Multer, Http, Socket.io, Nodemailer, Bcrypt

## How to Run the project

1. Install:
- VSCode at https://code.visualstudio.com/download
- Git at https://git-scm.com/downloads
- Node.js at https://nodejs.org/en/download/

2. Clone this repo from your command line.

3. Open the project with VSCode, open the IDE's terminal and run the command `npm install`

4. Create a new file in the public project directory and call it `.env`. 

5. Connect your project to the database:
- Create a MongoDB Atlas account at https://mongodb.com
- Connect your project to the MongoDB Cluster by clicking on the "connect" button, choosing the "connect to your application" option and copying the link.
- Inside the .env file, make a new variable called `DATABASE_URL` and assign it (=) to the link you copied from MongoDB, making sure to replace the 'username' and 'password' fields in the url to your database access credentials. 
- Full MongoDB setup tutorial at https://www.youtube.com/watch?v=2QQGWYe7IDU&ab_channel=TraversyMedia

6. Make an hotmail for your project and add 2 variables to your .env file:\
`MAIL_USER=<your-email-address>`\
`MAIL_PASS=<your-password>`

7. Run the project by typing "npm run devStart" and going to http://localhost:8000/ on your browser.

## How to use main features

### Admin Dashboard
1. Make a new Patient Account
2. Go to the MongoDB and edit that account's userType attribute to "admin"
3. Login with that account
4. Click 'Admin Dashboard' on the navbar
5. You can now see a list of every user that signed up to your application
6. You can Create new users (even admin users), edit and delete existing users

### Shopping Cart System / Chat
1. Checkout, then live chat. Follow these directions.
2. Sign in as a patient 
3. Visit the "Therapist" Page and click "purchase session" under the therapist card.
4. Once you click purchase session you will be redirected to the checkout page. 
4. a - At this point you can test that the checkout is saved by logging out and logging back in or visiting other pages and returning to the "checkout" page afterward. 
4. b - You can also delete your cart by clicking on the 'remove' button
5. Then click "1 year" in the package plan dropdown. This will allow you to chat with your selected therapist for 15 minutes.
6. After that click "confirm order" 
7. If you are in mobile view, click the menu in the bottom right.
8. Then click the chat sessions icon
9. Sign into the therapist using another private browser window.
10. Sign into the therapist account purchased
11. click the chat sessions icon located in the bottom right of the screen or in the mobile navbar inside the nav bar icon labeled "chat session"
12. Open both windows, the therapist and patient side by side.
13. Test sending messages back and forth (remember you only have 15 minutes).
14. BONUS. you can click the messages to see when they were sent. 
15. When your session is over a warning will be displayed.


### Custom user profile
1. Click 'Login' on the navbar
2. Click 'Sign up' on the navbar
3. Make a new account of any type (patient or therapist)
4. Log into the account you just created
5. Click 'Account' on the navbar
6. Change some information on the input fields
7. Add a profile picture
8. Click 'Save'
9. Refresh and see that your information was changed on the DB


### Easter Egg
1. Click 'Login' on the navbar
2. Click 'Sign up' on the navbar
3. Type 'batman' in the username field
4. Get ***mindblown***

## How to contribute
Pull requests are welcome. Please divide your PRs in 3 sections: `Problem`, `Solution`, `Testing`.

