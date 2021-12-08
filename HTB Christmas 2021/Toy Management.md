# HackTheBox Christmas 2021 CTF - Toy Management

## Summary 
This challenge was a fairly simple one, in that it was a simple SQL injection authentication bypass. Source code review could very easily be skipped here however for those who are newer, I'll give a breakdown.

Our payload is a very simple `' OR 1 -- -` as the username, this bypasses authentication and grants us the flag.

## Code Review

When looking at the challenge source, we can see that this is a NodeJS based application. This is given away by a common node-application file tree. The main giveaways here being package.json, and index.js in the root.
```
├───helpers
│   └───JWTHelper.js
├───middleware
│   └───AuthMiddleware.js
├───routes
│   └───index.js
├───static
│   ├───css
│   ├───images
│   └───js
├───views
├───database.js
├───database.sql
├───index.js
└───package.json
```

The first thing I checked here was `database.sql` and `database.js`, reason being that it's unlikely someone making a CTF is going to go through the pain of setting this up without it being essential somehow. Looking inside of `database.sql` we see the following snippet:
```sql
INSERT INTO `toylist` (`id`, `toy`, `receiver`, `location`, `approved`) VALUES
(1,  'She-Ra, Princess of Power', 'Elaina Love', 'Houston', 1),
[...SNIP...]
(6, 'Polly Pocket dolls', 'Aracely Monroe', 'El Paso', 1),
(7, 'HTB{f4k3_fl4g_f0r_t3st1ng}', 'HTBer', 'HTBland', 0);
```
This gives us our goal, we have to read the `toylist` table somehow. Taking a quick look at `database.js` we see the following.
```js
	async loginUser(user, pass) {
		return new Promise(async (resolve, reject) => {
			let stmt = `SELECT username FROM users WHERE username = '${user}' and password = '${pass}'`;
			this.connection.query(stmt, (err, result) => {
				if(err)
					reject(err)
				try {
					resolve(JSON.parse(JSON.stringify(result)))
				}
				catch (e) {
					reject(e)
				}
			})
		});
	}

	async getUser(user) {
		return new Promise(async (resolve, reject) => {
			let stmt = `SELECT * FROM users WHERE username = '${user}'`;
			this.connection.query(stmt, (err, result) => {
				if(err)
					reject(err)
				try {
					resolve(JSON.parse(JSON.stringify(result)))
				}
				catch (e) {
					reject(e)
				}
			})
		});
	}
```
As we can see, this shows there is SQL injection within both the `loginUser` and `getUser` methods. So let's look at how to interact with those.

Next place to look is `routes/index.js`, reason being that this is likely a NodeJS "router", meaning it should contain functionality of each endpoint for the application. Within that file we see the following:
```js
router.post('/api/login', async (req, res) => {
	const { username, password } = req.body;
	if (username && password) {
		passhash = crypto.createHash('md5').update(password).digest('hex');
		return db.loginUser(username, passhash)
        [...SNIP...]        
```
We can see that whatever we enter as a username to the `loginUser` endpoint appears to be passed _directly_ to the previously mentioned `loginUser` method from `database.js`. Whilst at this point we could again assume a simple `' OR 1 -- -` would work, which it will, the reason why can be further elaborated.

Further down in `routes/index.js` we see the code for the `/api/toylist` endpoint. This shows us that the user must be authenticated as the `admin` user:
```js
router.get('/api/toylist', AuthMiddleware, async (req, res) => {
	return db.getUser(req.data.username)
		.then(user => {
			approved = 1;
			if (user[0].username == 'admin') approved = 0;
			return db.listToys(approved)
            	.then(toyInfo => {
					return res.json(toyInfo);
				})
            [...SNIP...]
```
The reason the simple `' OR 1 -- -` works is because we end up producing the following SQL statement within `database.js`
```SQL
SELECT username FROM users WHERE username = '' OR 1 -- -' and password = '${pass}'
```
Usually, this would cause issues as this returns the rows of _all_ users in the database, and thus may cause issues later on in the authentication process, however as we can see, the line `if (user[0].username == 'admin') approved = 0;` in `routes/index.js` highlights that the first row from the returned query will be selected anyways.

In a more realistic scenario where this may not be the case, you could work around this by using `admin' -- -` as your payload, which would give the following query:
```SQL
SELECT username FROM users WHERE username = 'admin' -- -
```
This would return the exactly one row we need, and thus be a free win.

# Performing The Attack

Sending POST request to `/api/login` with a username of `admin' -- -` gives us a valid, signed JWT of the admin user, we can now navigate to `/api/toylist` and get the flag.

`HTB{1nj3cti0n_1s_in3v1t4bl3}`