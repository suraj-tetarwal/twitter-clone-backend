const express = require('express')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const path = require('path')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
app.use(express.json())

const dbPath = path.join(__dirname, 'twitterClone.db')

let db = null

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })

    app.listen(3000, () => {
      console.log('Server running on port 3000')
    })
  } catch (e) {
    console.log(`DB Error: ${e.message}`)
    process.exit(1)
  }
}

initializeDBAndServer()

// API 1
app.post('/register', async (request, response) => {
  const {username, password, name, gender} = request.body

  const getUserQuery = `
    SELECT
      user_id
    FROM
      user
    WHERE
      username = ?;
  `

  const user = await db.get(getUserQuery, [username])

  if (user) {
    response.status(400).send('User already exists')
    return
  }

  if (password.length < 6) {
    response.status(400).send('Password is too short')
    return
  }

  const hashedPassword = await bcrypt.hash(password, 10)

  console.log(hashedPassword)

  const createUserQuery = `
    INSERT INTO user (name, username, password, gender)
    VALUES (?, ?, ?, ?);
  `

  await db.run(createUserQuery, [name, username, hashedPassword, gender])

  response.status(200).send('User created successfully')
})

// API 2
app.post('/login', async (request, response) => {
  const {username, password} = request.body

  const getUserQuery = `
    SELECT
      *
    FROM
      user
    WHERE
      username = ?;
  `

  const user = await db.get(getUserQuery, [username])

  if (!user) {
    response.status(400).send('Invalid user')
    return
  }

  const isPasswordMatches = await bcrypt.compare(password, user.password)
  if (isPasswordMatches) {
    const payload = {
      userId: user.user_id,
      username: user.name,
    }

    const jwtToken = jwt.sign(payload, 'MY_SECRET_KEY')

    response.send({jwtToken})
  } else {
    response.status(400).send('Invalid password')
  }
})

// Authenticate User Middleware
const authenticateToken = (request, response, next) => {
  let jwtToken
  const authHeader = request.headers['authorization']
  if (authHeader) {
    jwtToken = authHeader.split(' ')[1]
    if (jwtToken) {
      jwt.verify(jwtToken, 'MY_SECRET_KEY', async (error, payload) => {
        if (error) {
          response.status(401).send('Invalid JWT Token')
        } else {
          request.userId = payload.userId
          request.username = payload.username
          next()
        }
      })
    } else {
      response.status(401).send('Invalid JWT Token')
    }
  } else {
    response.status(401).send('Invalid JWT Token')
  }
}

// API 3
app.get('/user/tweets/feed', authenticateToken, async (request, response) => {
  const {userId} = request

  const getTweetsListQuery = `
    SELECT
      user.username,
      tweet.tweet,
      tweet.date_time AS dateTime
    FROM
      user
      INNER JOIN follower ON user.user_id = follower.following_user_id
      INNER JOIN tweet ON follower.following_user_id = tweet.user_id
    WHERE
      follower.follower_user_id = ?
    ORDER BY
      tweet.date_time DESC
    LIMIT 4;
  `

  const tweetsList = await db.all(getTweetsListQuery, [userId])

  response.send(tweetsList)
})

// API 4
app.get('/user/following', authenticateToken, async (request, response) => {
  const {userId} = request

  const getUserFollowingListQuery = `
    SELECT
      user.name
    FROM
      user INNER JOIN follower
      ON user.user_id = follower.following_user_id
    WHERE
      follower.follower_user_id = ?;
  `

  const result = await db.all(getUserFollowingListQuery, [userId])

  response.send(result)
})

// API 5
app.get('/user/followers', authenticateToken, async (request, response) => {
  const {userId} = request

  const getUserFollowerListQuery = `
    SELECT
      user.name
    FROM
      user INNER JOIN follower
      ON user.user_id = follower.follower_user_id
    WHERE
      follower.following_user_id = ?;
  `

  const result = await db.all(getUserFollowerListQuery, [userId])

  response.send(result)
})

// API 6
app.get('/tweets/:tweetId', authenticateToken, async (request, response) => {
  const {userId} = request
  const {tweetId} = request.params

  const checkQuery = `
    SELECT
      *
    FROM
      follower
      INNER JOIN tweet
      ON follower.following_user_id = tweet.user_id
    WHERE
      follower.follower_user_id = ? AND tweet.tweet_id = ?;
  `

  const result = await db.get(checkQuery, [userId, tweetId])

  if (!result) {
    response.status(401).send('Invalid Request')
    return
  }

  const getTweetQuery = `
    SELECT
      tweet.tweet,
      COUNT(DISTINCT like.like_id) AS likes,
      COUNT(DISTINCT reply.reply_id) AS replies,
      tweet.date_time AS dateTime
    FROM
      tweet
      LEFT JOIN reply ON tweet.tweet_id = reply.tweet_id
      LEFT JOIN like ON tweet.tweet_id = like.tweet_id
    WHERE
      tweet.tweet_id = ?
    GROUP BY
      tweet.tweet_id;
  `

  const tweet = await db.get(getTweetQuery, [tweetId])

  response.send(tweet)
})

// API 7
app.get(
  '/tweets/:tweetId/likes',
  authenticateToken,
  async (request, response) => {
    const {userId} = request
    const {tweetId} = request.params

    const checkQuery = `
      SELECT
        *
      FROM
        follower
        INNER JOIN tweet
        ON follower.following_user_id = tweet.user_id
      WHERE
        follower.follower_user_id = ? AND tweet.tweet_id = ?;
    `

    const tweet = await db.get(checkQuery, [userId, tweetId])

    if (!tweet) {
      response.status(401).send('Invalid Request')
      return
    }

    const getTweetQuery = `
      SELECT
        user.username
      FROM
        user
        INNER JOIN like
        ON user.user_id = like.user_id 
      WHERE 
        like.tweet_id = ?;;
      `

    const result = await db.all(getTweetQuery, [tweetId])

    const likes = result.map(eachUsername => eachUsername.username)

    response.send({likes})
  },
)

// API 8
app.get(
  '/tweets/:tweetId/replies',
  authenticateToken,
  async (request, response) => {
    const {userId} = request
    const {tweetId} = request.params

    const checkQuery = `
      SELECT
        *
      FROM
        follower
        INNER JOIN tweet
        ON follower.following_user_id = tweet.user_id
      WHERE
        follower.follower_user_id = ? AND tweet.tweet_id = ?;
    `

    const tweet = await db.get(checkQuery, [userId, tweetId])

    if (!tweet) {
      response.status(401).send('Invalid Request')
      return
    }

    const getRepliesQuery = `
      SELECT
        user.name,
        reply.reply
      FROM
        user
        INNER JOIN reply 
        ON user.user_id = reply.user_id
      WHERE
        reply.tweet_id = ?;
    `

    const repliesList = await db.all(getRepliesQuery, [tweetId])

    response.send({replies: repliesList})
  },
)

// API 9
app.get('/user/tweets', authenticateToken, async (request, response) => {
  const {userId} = request

  const getUserTweetsListQuery = `
    SELECT
      tweet.tweet,
      COUNT(DISTINCT like.like_id) AS likes,
      COUNT(DISTINCT reply.reply_id) AS replies,
      tweet.date_time AS dateTime
    FROM
      tweet 
      LEFT JOIN reply ON tweet.tweet_id = reply.tweet_id
      LEFT JOIN like ON tweet.tweet_id = like.tweet_id
    WHERE
      tweet.user_id = ?
    GROUP BY
      tweet.tweet_id;
  `

  const result = await db.all(getUserTweetsListQuery, [userId])

  response.send(result)
})

// API 10
app.post('/user/tweets', authenticateToken, async (request, response) => {
  const {userId} = request
  const {tweet} = request.body

  const createTweetQuery = `
    INSERT INTO tweet (tweet, user_id)
    VALUES (?, ?);
  `

  await db.run(createTweetQuery, [tweet, userId])

  response.send('Created a Tweet')
})

// API 11
app.delete('/tweets/:tweetId', authenticateToken, async (request, response) => {
  const {userId} = request
  const {tweetId} = request.params

  const getTweetQuery = `
    SELECT
      tweet_id
    FROM
      tweet
    WHERE
      tweet_id = ? AND user_id = ?;
  `

  const tweet = await db.get(getTweetQuery, [tweetId, userId])

  if (!tweet) {
    response.status(401).send('Invalid Request')
    return
  }

  const deleteTweetQuery = `
    DELETE FROM tweet
    WHERE tweet_id = ? AND user_id = ?;
  `

  await db.run(deleteTweetQuery, [tweetId, userId])

  response.send('Tweet Removed')
})
