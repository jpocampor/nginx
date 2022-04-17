async function generate_hs256_jwt(payload, key, valid_time) {
  let header = { typ : "JWT", alg : "HS256" };
  let claims = Object.assign(payload, {exp: Math.floor(Date.now()/1000) + valid_time})

  let s = [header, claims].map(JSON.stringify)
			  .map(v=>Buffer.from(v).toString('base64url'))
			  .join('.');
  let wc_key = await crypto.subtle.importKey(
	  'raw',
	  key,
	  {name: 'HMAC', hash: 'SHA-256'},
	  false,
	  ['sign']);

  let sign = await crypto.subtle.sign({name: 'HMAC'}, wc_key, s);

  return s +  '.' + Buffer.from(sign).toString('base64url');
}

async function generate_jwt_token(r) {
  let split = function(item){
    let obj = {};
    let items = item.split("=");
    const key = items[0], value = items[1];
    obj[key] = value;
    return obj;
  }

  let x_user_array = (r.headersIn["X-User"].split(",")).map(split);
  let x_user_obj = x_user_array.reduce((k,v)=> Object.assign(k,v), Object.create(null));
  let jwt = await generate_hs256_jwt(x_user_obj, "SomeKey", 600);
  r.headersOut["jwt"] = jwt;
  r.headersOut["X-User"] = r.headersIn["X-User"];
  r.return(200, JSON.stringify({x_user: x_user_obj}));
}

export default {generate_jwt_token};
