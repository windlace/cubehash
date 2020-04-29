// How to generate IV for CubeHash80+8/1+80-256

// Here is desired IV.
// we will compute it manually (32-bit integers).
//
// Init vector was computed by 10r rounds as described in the specification
// var init = [
//   -2096419883, 658334063, -679114902, 1246757400,
//   -1523021469, -289996037, 1196718146, 1168084361,
//   -2027445816, -1170162360, -822837272, 625197683,
//   1543712850, -1365258909, 759513533, -424228083,
//   -13765010209, -2824905881, -9887154026, 19352563566,
//   5669379852, -31581549269, 21359466527, 10648459874,
//   -8561790247, 9779462261, -22434204802, -4124492433,
//   19608647852, 9541915967, 5144979599, -4355863926
// ];

var init = [
   32,            1,            8,  0,
    0,            0,            0,  0,
    0,            0,            0,  0,
    0,            0,            0,  0,
    0,            0,            0,  0,
    0,            0,            0,  0,
    0,            0,            0,  0,
    0,            0,            0,  0,
];

function rotate(a, b) {
  return (a << b) | (a >>> (32 - b));
}

function intToHex(v) {
  var s = '';

  for (; v !== 0; v >>>= 8) {
    s += ((v >> 4) & 0xF).toString(16) + (v & 0xF).toString(16);
  }

  return s;
}

function swap(arr, i, j) {
  var tmp = arr[i];
  arr[i] = arr[j];
  arr[j] = tmp;
  return arr;
}

function transform(state) {
  var i, r,
    y = new Array(16);

  for (r = 0;r < 8; r += 1) {
    for (i = 0; i < 16; i += 1) { state[i + 16] += y[i^8] = state[i]; }
    for (i = 0; i < 16; i += 1) { state[i]       = rotate(y[i],  7)^state[i + 16]; }
    for (i = 0; i < 16; i += 1) { y[i^2]         = state[i + 16]; }
    for (i = 0; i < 16; i += 1) { state[i + 16]  = y[i] + state[i]; }
    for (i = 0; i < 16; i += 1) { y[i^4]         = state[i]; }
    for (i = 0; i < 16; i += 1) { state[i]       = rotate(y[i], 11)^state[i + 16]; }
    for (i = 0; i < 16; i += 2) {
        swap(state, i + 16, i + 17);
    }
  }

  for (i = 0; i < 16; i += 1) {
    y[i] = 0;
  }

  return state;
}

function hash(data) {
  // init state
  var i,
      s = '',
      state = new Array(32);

  for (i = 0; i < 32; i += 1) {
      state[i] = init[i];
  }

  // update with data
  // data += String.fromCharCode(128);

  // for (i = 0; i < data.length; i += 1) {
      // state[0] ^= data.charCodeAt(i);
      // state = transform(state);
  // }

  // finalize
  // state[31] ^= 1;

  for (i = 0; i < 10; i += 1) {
      state = transform(state);
  }

  return state;

  // convert to hex
  for (i = 0; i < 8; i += 1) {
      s += intToHex(state[i]);
  }
  return s;
}

console.log(hash(''));
