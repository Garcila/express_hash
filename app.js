const express = require( 'express' );
const bcrypt = require( 'bcrypt' );
const app = express();

app.use( express.json() );

const db = [];

app.get( '/db', ( req, res ) => {
  res.json( db );
} );

//TODO: terrible way! Never store passwords in plaintext!
app.post( '/unsafe_db', ( req, res ) => {
  const user = { name: req.body.name, password: req.body.password };
  db.push( user );
  res.sendStatus( 201 );
} );

//TODO: using a password hash instead of plaintext
app.post( '/safe_db', async ( req, res ) => {
  const password = req.body.password;

  const salt = await bcrypt.genSaltSync( 12 );
  const hash = await bcrypt.hashSync( password, salt );

  const user = { name: req.body.name, password: hash };
  db.push( user );
  res.sendStatus( 201 );
} );

//TODO: log in user if password is correct
app.post( '/login', async ( req, res ) => {
  const userName = req.body.name;
  // find the user in our db
  const user = db.find( user => user.name === userName );

  if ( user ) {
    const password = req.body.password;
    const isMatch = await bcrypt.compare( password, user.password );
    if ( isMatch ) {
      res.send( { success: true } );
    } else {
      res.send( { success: false } );
    }
  }
} );

app.listen( 3000, () => {
  console.log( 'Example app listening on port 3000!' );
} );