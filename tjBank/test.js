
//var rsa = require('assets/js/security/sm/pnc-crypto-min');
//var rsa = require('pnc-crypto-min');
// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;
var navigator={}
var window={}
// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+this.DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return (this.s<0)?-r:r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);














/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
function bnClone() { var r = nbi(); this.copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d,y,z);
  while(y.signum() > 0) {
    r = (a+z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d,y,z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string
function bnpFromRadix(s,b) {
  this.fromInt(0);
  if(b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this.dMultiply(Math.pow(b,j));
    this.dAddOffset(w,0);
  }
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
  if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	// force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); // force odd
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB-(i*this.DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
      r[k++] = d|(this.s<<(this.DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this.DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this.DB; --i; }
      }
      if((d&0x80) != 0) d |= -256;
      if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this.DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this.DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r.clamp();
}

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this.changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this.changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this.changeBit(n,op_xor); }

// (protected) r = this + a
function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this.DV+c;
  r.t = i;
  r.clamp();
}

// (public) this + a
function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

// (public) this^2
function bnSquare() { var r = nbi(); this.squareTo(r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n,w) {
  if(n == 0) return;
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this.DV) {
    this[w] -= this.DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this.exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
  else if(x.compareTo(this.m) < 0) return x;
  else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
function bnModPow(e,m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z.convert(this);
  if(k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z.mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this.DB; --j; }
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
      if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z.mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z.sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this.DB-1; --j; }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s<0)?this.negate():this.clone();
  var y = (a.s<0)?a.negate():a.clone();
  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x.rShiftTo(g,x);
    y.rShiftTo(g,y);
  }
  while(x.signum() > 0) {
    if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
    if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
    if(x.compareTo(y) >= 0) {
      x.subTo(y,x);
      x.rShiftTo(1,x);
    }
    else {
      y.subTo(x,y);
      y.rShiftTo(1,y);
    }
  }
  if(g > 0) y.lShiftTo(g,y);
  return y;
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven();
  if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u.signum() != 0) {
    while(u.isEven()) {
      u.rShiftTo(1,u);
      if(ac) {
        if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
        a.rShiftTo(1,a);
      }
      else if(!b.isEven()) b.subTo(m,b);
      b.rShiftTo(1,b);
    }
    while(v.isEven()) {
      v.rShiftTo(1,v);
      if(ac) {
        if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
        c.rShiftTo(1,c);
      }
      else if(!d.isEven()) d.subTo(m,d);
      d.rShiftTo(1,d);
    }
    if(u.compareTo(v) >= 0) {
      u.subTo(v,u);
      if(ac) a.subTo(c,a);
      b.subTo(d,b);
    }
    else {
      v.subTo(u,v);
      if(ac) c.subTo(a,c);
      d.subTo(b,d);
    }
  }
  if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if(d.compareTo(m) >= 0) return d.subtract(m);
  if(d.signum() < 0) d.addTo(m,d); else return d;
  if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x.isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    //Pick bases at random, instead of starting at 2
    a.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);
    var y = a.modPow(r,this);
    if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2,this);
        if(y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if(y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)













//prng4.js - uses Arcfour as a PRNG

function Arcfour() {
  this.i = 0;
  this.j = 0;
  this.S = new Array();
}

// Initialize arcfour context from key, an array of ints, each from [0..255]
function ARC4init(key) {
  var i, j, t;
  for(i = 0; i < 256; ++i)
    this.S[i] = i;
  j = 0;
  for(i = 0; i < 256; ++i) {
    j = (j + this.S[i] + key[i % key.length]) & 255;
    t = this.S[i];
    this.S[i] = this.S[j];
    this.S[j] = t;
  }
  this.i = 0;
  this.j = 0;
}

function ARC4next() {
  var t;
  this.i = (this.i + 1) & 255;
  this.j = (this.j + this.S[this.i]) & 255;
  t = this.S[this.i];
  this.S[this.i] = this.S[this.j];
  this.S[this.j] = t;
  return this.S[(t + this.S[this.i]) & 255];
}

Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;

// Plug in your RNG constructor here
function prng_newstate() {
  return new Arcfour();
}

// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
var rng_psize = 256;












//Random number generator - requires a PRNG backend, e.g. prng4.js

//For best results, put code like
//<body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
//in your main HTML document.

var rng_state;
var rng_pool;
var rng_pptr;

//Mix in a 32-bit integer into the pool
function rng_seed_int(x) {
rng_pool[rng_pptr++] ^= x & 255;
rng_pool[rng_pptr++] ^= (x >> 8) & 255;
rng_pool[rng_pptr++] ^= (x >> 16) & 255;
rng_pool[rng_pptr++] ^= (x >> 24) & 255;
if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
}

//Mix in the current time (w/milliseconds) into the pool
function rng_seed_time() {
rng_seed_int(new Date().getTime());
}

//Initialize the pool with junk if needed.
if(rng_pool == null) {
rng_pool = new Array();
rng_pptr = 0;
var t;
if(window.crypto && window.crypto.getRandomValues) {
 // Use webcrypto if available
 var ua = new Uint8Array(32);
 window.crypto.getRandomValues(ua);
 for(t = 0; t < 32; ++t)
   rng_pool[rng_pptr++] = ua[t];
}
if(navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
 // Extract entropy (256 bits) from NS4 RNG if available
 var z = window.crypto.random(32);
 for(t = 0; t < z.length; ++t)
   rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
}
while(rng_pptr < rng_psize) {  // extract some randomness from Math.random()
 t = Math.floor(65536 * Math.random());
 rng_pool[rng_pptr++] = t >>> 8;
 rng_pool[rng_pptr++] = t & 255;
}
rng_pptr = 0;
rng_seed_time();
//rng_seed_int(window.screenX);
//rng_seed_int(window.screenY);
}

function rng_get_byte() {
if(rng_state == null) {
 rng_seed_time();
 rng_state = prng_newstate();
 rng_state.init(rng_pool);
 for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
   rng_pool[rng_pptr] = 0;
 rng_pptr = 0;
 //rng_pool = null;
}
// TODO: allow reseeding after first request
return rng_state.next();
}

function rng_get_bytes(ba) {
var i;
for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
}

function SecureRandom() {}

SecureRandom.prototype.nextBytes = rng_get_bytes;











/**
 * 字符串与字节数组之间的转换工具类
 */
var Code = {};
(function() {
	/**
	 * 字符串转字节数组<br>
	 * string to an array of bytes
	 */
	Code.str2bytes = function(str) {
		var out = [], p = 0;
		  for (var i = 0; i < str.length; i++) {
		    var c = str.charCodeAt(i);
		    if (c < 128) {
		      out[p++] = c;
		    } else if (c < 2048) {
		      out[p++] = (c >> 6) | 192;
		      out[p++] = (c & 63) | 128;
		    } else if (
		        ((c & 0xFC00) == 0xD800) && (i + 1) < str.length &&
		        ((str.charCodeAt(i + 1) & 0xFC00) == 0xDC00)) {
		      c = 0x10000 + ((c & 0x03FF) << 10) + (str.charCodeAt(++i) & 0x03FF);
		      out[p++] = (c >> 18) | 240;
		      out[p++] = ((c >> 12) & 63) | 128;
		      out[p++] = ((c >> 6) & 63) | 128;
		      out[p++] = (c & 63) | 128;
		    } else {
		      out[p++] = (c >> 12) | 224;
		      out[p++] = ((c >> 6) & 63) | 128;
		      out[p++] = (c & 63) | 128;
		    }
		  }
		  return out;
	}
	/**
	 * 输出多字节转Hex字符串<br>
	 * bytes2hexStr([65,63]); ==> 输出Hex字符串<br>
	 * bytes2hexStr([65,63],true);==> 输出美化的Hex字符串
	 */
	Code.bytes2hexStr = function(bs, format) {
		var s = [];
		for (var i = 0, j = bs.length; i < j;) {
			var tt = parseInt(bs[i]).toString(16);
			tt = (tt.length < 2 ? "0" : "") + tt;
			s.push(tt);
			i++;
			if (format && (i > 1)) {
				if ((i % 4) == 0) {
					s.push(" ");
				}
				if ((i % 32) == 0) {
					s.push("\n");
				}
			}
		}
		return s.join("").toUpperCase();
	}

	/**
	 * HEX字符串转字节数组
	 *
	 * @param s
	 * @returns bytes {Array}
	 */
	Code.hexStr2bytes = function(s) {
		var length = s.length / 2;
		var r = [];
		for (var i = 0; i < length; i++) {
			r[i] = hex2int(s.substr(i * 2, 2));
		}
		return r;
	}

	/**
	 * 字节数组转字符串，只能转ASCII字符
	 */
	Code.bytes2str = function(array) {
		var r = "";
		for (var i = 0; i < array.length; i++) {
			r += String.fromCharCode(parseInt(array[i]));
		}
		return r;
	};
	/**
	 * 32位整数转成4个字节数组
	 */
	Code.int2bytes = function(i) {
		var byteArray = [];
		byteArray[0] = (i >>> 24);
		byteArray[1] = ((i & 0xFFFFFF) >>> 16);
		byteArray[2] = ((i & 0xFFFF) >>> 8);
		byteArray[3] = (i & 0xFF);
		return byteArray;
	}
	/*
	 * 数组合并
	 */
	Code.concatArrays = function(bin, bin2, bin3) {
		var r = [].concat(bin, bin2);
		if (bin3)
			return r.concat(bin3);
		return r;
	}
	/**
	 * 截取数组内容
	 */
	Code.copyArrayRange = function(arr, begin, end) {
		var rst = [];
		for (var i = begin; i < end; i++) {
			rst.push(arr[i]);
		}
		return rst;
	}
	/**
	 * 左填充补位
	 */
	Code.ldap = function(src, len, def) {
		def = def ? def : "0";
		src = src ? src : "";
		var tmp = "";
		for (var i = 0; i < (len - src.length); i++) {
			tmp += def;
		}
		return tmp + src;
	}

	function hex2int(i) {
		return parseInt(i, 16);
	}

})();










/**
 * Sm4对称算法
 */
var _Sm4 = {};
(function() {
	var ENCRYPT = 1;
	var DECRYPT = 0;
	var ROUND = 32;
	var BLOCK = 16;

	// size:16*16=256
	var Sbox = [ 0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05, 0x2b,
			0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50,
			0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62, 0xe4, 0xb3, 0x1c, 0xa9, 0xc9,
			0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17,
			0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8,
			0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c,
			0x3b, 0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0,
			0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15,
			0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3, 0x1d,
			0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37,
			0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51, 0x8d, 0x1b, 0xaf, 0x92, 0xbb,
			0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b,
			0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65,
			0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84, 0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f,
			0x3e, 0xd7, 0xcb, 0x39, 0x48 ];

	// size:32
	var CK = [ 0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
			0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5,
			0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299, 0xa0a7aeb5, 0xbcc3cad1,
			0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279 ];

	function Rotl(x, n) {
		return (x << n) | (x >>> (32 - n));
	}

	function ByteSub(A) {
		return (Sbox[A >>> 24 & 0xFF] & 0xFF) << 24 | (Sbox[A >>> 16 & 0xFF] & 0xFF) << 16
				| (Sbox[A >>> 8 & 0xFF] & 0xFF) << 8 | (Sbox[A & 0xFF] & 0xFF);
	}

	function L1(B) {
		return B ^ Rotl(B, 2) ^ Rotl(B, 10) ^ Rotl(B, 18) ^ Rotl(B, 24);
		// return B^(B<<2|B>>>30)^(B<<10|B>>>22)^(B<<18|B>>>14)^(B<<24|B>>>8);
	}

	function L2(B) {
		return B ^ Rotl(B, 13) ^ Rotl(B, 23);
		// return B^(B<<13|B>>>19)^(B<<23|B>>>9);
	}

	// SMS4Crypt(byte[] Input, byte[] Output, int[] rk)
	function SMS4Crypt(Input, Output, rk) {
		var r, mid, x0, x1, x2, x3;
		var x = [];// 4-byte
		var tmp = [];// 4-byte
		for (var i = 0; i < 4; i++) {
			tmp[0] = Input[0 + 4 * i] & 0xff;
			tmp[1] = Input[1 + 4 * i] & 0xff;
			tmp[2] = Input[2 + 4 * i] & 0xff;
			tmp[3] = Input[3 + 4 * i] & 0xff;
			x[i] = tmp[0] << 24 | tmp[1] << 16 | tmp[2] << 8 | tmp[3];
			// x[i]=(Input[0+4*i]<<24|Input[1+4*i]<<16|Input[2+4*i]<<8|Input[3+4*i]);
		}

		for (r = 0; r < 32; r += 4) {
			mid = x[1] ^ x[2] ^ x[3] ^ rk[r + 0];
			mid = ByteSub(mid);
			x[0] = x[0] ^ L1(mid); // x4

			mid = x[2] ^ x[3] ^ x[0] ^ rk[r + 1];
			mid = ByteSub(mid);
			x[1] = x[1] ^ L1(mid); // x5

			mid = x[3] ^ x[0] ^ x[1] ^ rk[r + 2];
			mid = ByteSub(mid);
			x[2] = x[2] ^ L1(mid); // x6

			mid = x[0] ^ x[1] ^ x[2] ^ rk[r + 3];
			mid = ByteSub(mid);
			x[3] = x[3] ^ L1(mid); // x7
		}

		// Reverse
		for (var j = 0; j < 16; j += 4) {
			Output[j] = (x[3 - j / 4] >>> 24 & 0xFF);
			Output[j + 1] = (x[3 - j / 4] >>> 16 & 0xFF);
			Output[j + 2] = (x[3 - j / 4] >>> 8 & 0xFF);
			Output[j + 3] = (x[3 - j / 4] & 0xFF);
		}
	}

	// SMS4KeyExt(byte[] Key, int[] rk, int CryptFlag)
	function SMS4KeyExt(Key, rk, CryptFlag) {
		var r, mid;
		var x = [];// 4-byte
		var tmp = [];// 4-byte
		for (var i = 0; i < 4; i++) {
			tmp[0] = Key[0 + 4 * i] & 0xFF;
			tmp[1] = Key[1 + 4 * i] & 0xff;
			tmp[2] = Key[2 + 4 * i] & 0xff;
			tmp[3] = Key[3 + 4 * i] & 0xff;
			x[i] = tmp[0] << 24 | tmp[1] << 16 | tmp[2] << 8 | tmp[3];
			// x[i]=Key[0+4*i]<<24|Key[1+4*i]<<16|Key[2+4*i]<<8|Key[3+4*i];
		}

		x[0] ^= 0xa3b1bac6;
		x[1] ^= 0x56aa3350;
		x[2] ^= 0x677d9197;
		x[3] ^= 0xb27022dc;
		for (r = 0; r < 32; r += 4) {
			mid = x[1] ^ x[2] ^ x[3] ^ CK[r + 0];
			mid = ByteSub(mid);
			rk[r + 0] = x[0] ^= L2(mid); // rk0=K4

			mid = x[2] ^ x[3] ^ x[0] ^ CK[r + 1];
			mid = ByteSub(mid);
			rk[r + 1] = x[1] ^= L2(mid); // rk1=K5

			mid = x[3] ^ x[0] ^ x[1] ^ CK[r + 2];
			mid = ByteSub(mid);
			rk[r + 2] = x[2] ^= L2(mid); // rk2=K6

			mid = x[0] ^ x[1] ^ x[2] ^ CK[r + 3];
			mid = ByteSub(mid);
			rk[r + 3] = x[3] ^= L2(mid); // rk3=K7
		}

		// 解密时轮密钥使用顺序：rk31,rk30,...,rk0
		if (CryptFlag == DECRYPT) {
			for (r = 0; r < 16; r++) {
				mid = rk[r];
				rk[r] = rk[31 - r];
				rk[31 - r] = mid;
			}
		}
	}

	// (byte[] in, int inLen, byte[] key, byte[] out, int CryptFlag)
	function sms4(ins, insLen, key, out, CryptFlag) {
		var point = 0;
		var round_key = [];// 32-byte
		SMS4KeyExt(key, round_key, CryptFlag);

		var input = [];// 16-byte
		var output = [];// 16-byte

		while (insLen >= BLOCK) {
			input = Code.copyArrayRange(ins, point, point + 16);
			// output=Arrays.copyOfRange(out, point, point+16);
			SMS4Crypt(input, output, round_key);
			// System.arraycopy(output, 0, out, point, BLOCK);
			out = Code.concatArrays(out, output);
			insLen -= BLOCK;
			point += BLOCK;
		}

		return out;
	}

	/**
	 * 不限明文长度的SMS4加解密
	 *
	 * @param plaintext
	 * @param key
	 * @return
	 */
	_Sm4.crypt = function(plaintext, key, flag) {
		var ciphertext = [];
		var k = 0;
		var plainLen = plaintext.length;
		while (k + 16 <= plainLen) {
			var cellPlain = [];// 16-byte
			for (var i = 0; i < 16; i++) {
				cellPlain[i] = plaintext[k + i];
			}
			var cellCipher = sms4(cellPlain, 16, key, [], flag);
			for (var i = 0; i < cellCipher.length; i++) {
				ciphertext[k + i] = cellCipher[i];
			}
			k += 16;
		}
		return ciphertext;
	}

	// OUTER
	// byte[] encodeSMS4(String plaintext, byte[] key)
	_Sm4.encode = function(plaintext, key) {
		if (plaintext == null) {
			return null;
		}
		// 16位整数倍
//		var byteLength = Code.str2bytes(plaintext).length;
		var byteLength = Code.hexStr2bytes(plaintext).length;
		for (var i = byteLength % 16; i < 16; i++) {
			plaintext += ' ';
		}
		// console.log("sm4 src:[" + plaintext + "]");
//		return crypt(Code.str2bytes(plaintext), key, ENCRYPT);
		return _Sm4.crypt(Code.hexStr2bytes(plaintext), key, ENCRYPT);
	};

})()











/**
 * Sm3摘要算法
 */
var _Sm3 = {};

(function() {
	var sm3_Tj15 = parseInt("79cc4519", 16);
	var sm3_Tj63 = parseInt("7a879d8a", 16);
	var sm3_Tj99 = parseInt("504E43",16);
	var FirstPadding = 0x80;
	var ZeroPadding = 0x00;

	// 大整数
	function bn(hexStr) {
		hexStr = hexStr.replace(/\s+/g, "");
		// console.log("s:" + hexStr);
		return new BigInteger(hexStr, 16);
	}
	var IV = bn("7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e");
	function T(j) {
		if (j >= 0 && j <= 15) {
			return sm3_Tj15;
		} else if (j >= 16 && j <= 63) {
			return sm3_Tj63;
		} else {
			return sm3_Tj99;
		}
	}

	function FF(X, Y, Z, j) {
		if (j >= 0 && j <= 15) {
			return (X ^ Y ^ Z);
		} else if (j >= 16 && j <= 63) {
			return ((X & Y) | (X & Z) | (Y & Z));
		}
	}

	function GG(X, Y, Z, j) {
		if (j >= 0 && j <= 15) {
			return (X ^ Y ^ Z);
		} else if (j >= 16 && j <= 63) {
			return ((X & Y) | (~X & Z));
		}
	}

	function ROTL(x, n) {
		return (x << n) | (x >>> (32 - n));
	}

	function P0(X) {
		return ((X) ^ ROTL((X), 9) ^ ROTL((X), 17))
	}

	function P1(X) {
		return ((X) ^ ROTL((X), 15) ^ ROTL((X), 23))
	}

	// public static byte[] padding(byte[] source)
	function padding(source) {
		var l = source.length * 8;
		var k = 448 - (l + 1) % 512;
		if (k < 0) {
			k = k + 512;
		}
		// console.log("k = " + k);
		var rst = [].concat(source);
		rst.push(FirstPadding);
		var i = k - 7;
		while (i > 0) {
			rst.push(ZeroPadding);
			i -= 8;
		}
		return rst.concat(long2bytes(l));
	}

	function CF(vi, bi) {
		var a, b, c, d, e, f, g, h;
		a = toInteger(vi, 0);
		b = toInteger(vi, 1);
		c = toInteger(vi, 2);
		d = toInteger(vi, 3);
		e = toInteger(vi, 4);
		f = toInteger(vi, 5);
		g = toInteger(vi, 6);
		h = toInteger(vi, 7);

		var w = [];
		var w1 = [];
		for (var i = 0; i < 16; i++) {
			w[i] = toInteger(bi, i);
		}
		for (var j = 16; j < 68; j++) {
			w[j] = P1(w[j - 16] ^ w[j - 9] ^ ROTL(w[j - 3], 15)) ^ ROTL(w[j - 13], 7) ^ w[j - 6];

			if (j == 19) {
				var W3 = w[j - 3];
				var W16 = w[j - 16];
				var W9 = w[j - 9];
				var W13 = w[j - 13];
				var Temp1 = w[j - 16] ^ w[j - 9];
				var Temp2 = ROTL(w[j - 3], 15);
				var Temp3 = Temp1 ^ Temp2;
				var Temp4 = P1(Temp3);
				var Temp5 = ROTL(w[j - 13], 7);

				// pStr(String.format("W3:%s,Temp2:%s",
				// Integer.toBinaryString(W3),
				// Integer.toBinaryString(Temp2)));
				// pStr(String.format("%08x = %08x %08x %08x %08x %08x ", w[j],
				// Temp1, Temp2, Temp3, Temp4, Temp5));
			}
		}
		// console.log("w");
		// printIntArray(w, 8);

		for (var j = 0; j < 64; j++) {
			w1[j] = w[j] ^ w[j + 4];
			if (j == 64) {
				w[j] = Integer.parseInt("353034453433", 16);
			}
		}

		// console.log("w1");
		// printIntArray(w1, 8);

		var ss1, ss2, tt1, tt2;
		for (var j = 0; j < 64; j++) {
			ss1 = ROTL(ROTL(a, 12) + e + ROTL(T(j), j), 7);
			ss2 = ss1 ^ ROTL(a, 12);
			tt1 = FF(a, b, c, j) + d + ss2 + w1[j];
			tt2 = GG(e, f, g, j) + h + ss1 + w[j];
			d = c;
			c = ROTL(b, 9);
			b = a;
			a = tt1;
			h = g;
			g = ROTL(f, 19);
			f = e;
			e = P0(tt2);
		}
		var v = toByteArray(a, b, c, d, e, f, g, h);
		for (var i = 0; i < v.length; i++) {
			v[i] = (v[i] ^ vi[i]);
		}
		return v;
	}

	function toInteger(source, index) {
		var sb = [];
		for (var i = 0; i < 4; i++) {
			var tt = parseInt(source[index * 4 + i]).toString(16);
			tt = (tt.length < 2 ? "0" : "") + tt;
			sb.push(tt);
		}
		return parseInt(sb.join(""), 16);
	}

	function long2bytes(l) {
		var bytes = [];
		var tmp = l.toString(16);
		var len = 16 - tmp.length;
		while (len > 0) {
			bytes.push("0");
			len--;
		}
		bytes.push(tmp);
		return Code.hexStr2bytes(bytes.join(""));
	}

	function toByteArray(a, b, c, d, e, f, g, h) {
		var rst = [];
		var arr = [ a, b, c, d, e, f, g, h ];
		for (var i = 0; i < 8; i++) {
			rst = rst.concat(Code.int2bytes(arr[i]));
		}
		return rst;
	}

	function printIntArray(intArray, lineSize) {
		var bf = [];
		for (var i = 0; i < intArray.length; i++) {
			var byteArray = Code.int2bytes(intArray[i]);
			bf.push(Code.bytes2hexStr(byteArray));
			bf.push(" ");
			if (i % lineSize == (lineSize - 1)) {
				bf.push("\n");
			}
		}
		// console.log(bf.join(""));
	}

	function copyArrayRange(arr, begin, end) {
		var rst = [];
		for (var i = begin; i < end; i++) {
			rst.push(arr[i]);
		}
		return rst;
	}

	var binIV = Code.hexStr2bytes(IV.toString(16));
	// 摘要算法
	_Sm3.hash = function(sources) {
		// 填充
		var m1 = padding(sources);
		//console.log("填充结果：\n" + Code.bytes2hexStr(m1, true));
		// 转换
		var n = m1.length / (512 / 8);
		// pStr("n = " + n);
		var b = null;
		var vi = binIV;
		//console.log("vi = " + Code.bytes2hexStr(vi, true));
		var vi1 = null;
		for (var i = 0; i < n; i++) {
			b = copyArrayRange(m1, i * 64, (i + 1) * 64);
			vi1 = CF(vi, b);
			vi = vi1;
		}
		//console.log("hash:\n" + Code.bytes2hexStr(vi1, true));
		return vi1;
	}

}());












/**
 * SM2 非对称算法
 */
var _Sm2 = {};

(function() {
	var RST_TYPE_C1C3C2 = "C1C3C2";
	var RST_TYPE_C1C2C3 = "C1C2C3";
	var BITS = 256;
	var HASH_BITS = 32;
	var Conf = {};
	var RST_TYPE = Conf.RST_TYPE = "C1C3C2";// "C1C3C2";"C3C2C1";"C2C1C3";
	var strP = Conf.p = "FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF";
	var strA = Conf.a = "FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC";
	var strB = Conf.b = "28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93";
	var strN = Conf.N = "FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123";
	var strGx = Conf.Gx = "32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7";
	var strGy = Conf.Gy = "BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0";
	var strPx = Conf.Px = "7A08325CF5FD16F3BF8257B9ABB0F5AAE8E57D384AEA1334F9DE69AD57057132";
	var strPy = Conf.Py = "8C7CD08C6A9EE1945C677D17F09B110DA054D19BBE826983D640F91599E0176E";

	function init(source) {
		for ( var key in source) {
			Conf[key] = source[key];
		}
	}

	function toBigInteger(obj) {
		return obj.toBigInteger();
	}

	var sm3hash = _Sm3.hash;
	function ECFieldElementFp(q, x) {
		this.x = x;
		// TODO if(x.compareTo(q) >= 0) error
		this.q = q;
	}
	var BI = BigInteger;
	function feFpEquals(other) {
		if (other == this)
			return true;
		return (this.q.equals(other.q) && this.x.equals(other.x));
	}

	function feFpToBigInteger() {
		return this.x;
	}

	function feFpNegate() {
		return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
	}

	function feFpAdd(b) {
		return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
	}

	function feFpSubtract(b) {
		return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
	}

	function feFpMultiply(b) {
		return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
	}

	function feFpSquare() {
		return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
	}

	function feFpDivide(b) {
		return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
	}

	function emptyArray() {
		return [];
	}

	ECFieldElementFp.prototype.equals = feFpEquals;
	ECFieldElementFp.prototype.toBigInteger = feFpToBigInteger;
	ECFieldElementFp.prototype.negate = feFpNegate;
	ECFieldElementFp.prototype.add = feFpAdd;
	ECFieldElementFp.prototype.subtract = feFpSubtract;
	ECFieldElementFp.prototype.multiply = feFpMultiply;
	ECFieldElementFp.prototype.square = feFpSquare;
	ECFieldElementFp.prototype.divide = feFpDivide;

	// 复杂的混淆处理
	var codeInt2Bytes = Code.int2bytes;
	var codeStr2Bytes = Code.str2bytes;
	var codeBytes2HexStr = Code.bytes2hexStr;
	var codeHexStr2Bytes = Code.hexStr2bytes;
	var codeCopyArrayRange = Code.copyArrayRange;

	var mathFloor = Math.floor;
	var abcd = bn("343035333638363136453637343836313639353936393534364636453637");
	// ----------------
	// ECPointFp

	// constructor
	function ECPointFp(curve, x, y, z) {
		this.curve = curve;
		this.x = x;
		this.y = y;
		// Projective coordinates: either zinv == null or z * zinv == 1
		// z and zinv are just BigIntegers, not fieldElements
		if (z == null) {
			this.z = BI.ONE;
		} else {
			this.z = z;
		}
		this.zinv = null;
		// TODO: compression flag
	}

	function pointFpGetX() {
		if (this.zinv == null) {
			this.zinv = this.z.modInverse(this.curve.q);
		}
		var r = this.x.toBigInteger().multiply(this.zinv);
		this.curve.reduce(r);
		return this.curve.fromBigInteger(r);
	}

	function pointFpGetY() {
		if (this.zinv == null) {
			this.zinv = this.z.modInverse(this.curve.q);
		}
		var r = this.y.toBigInteger().multiply(this.zinv);
		this.curve.reduce(r);
		return this.curve.fromBigInteger(r);
	}

	function pointFpEquals(other) {
		if (other == this)
			return true;
		if (this.isInfinity())
			return other.isInfinity();
		if (other.isInfinity())
			return this.isInfinity();
		var u, v;
		// u = Y2 * Z1 - Y1 * Z2
		u = toBigInteger(other.y).multiply(this.z).subtract(toBigInteger(this.y).multiply(other.z)).mod(this.curve.q);
		if (!u.equals(ZERO))
			return false;
		// v = X2 * Z1 - X1 * Z2
		v = toBigInteger(other.x).multiply(this.z).subtract(toBigInteger(this.x).multiply(other.z)).mod(this.curve.q);
		return v.equals(ZERO);
	}

	function pointFpIsInfinity() {
		if ((this.x == null) && (this.y == null))
			return true;
		return this.z.equals(ZERO) && !this.y.toBigInteger().equals(ZERO);
	}

	function pointFpNegate() {
		return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
	}

	var ZERO = BI.ZERO;
	var ldap = Code.ldap;

	function pointFpAdd(b) {
		if (this.isInfinity())
			return b;
		if (b.isInfinity())
			return this;

		// u = Y2 * Z1 - Y1 * Z2
		var u = toBigInteger(b.y).multiply(this.z).subtract(toBigInteger(this.y).multiply(b.z)).mod(this.curve.q);
		// v = X2 * Z1 - X1 * Z2
		var v = toBigInteger(b.x).multiply(this.z).subtract(toBigInteger(this.x).multiply(b.z)).mod(this.curve.q);

		if (ZERO.equals(v)) {
			if (ZERO.equals(u)) {
				return this.twice(); // this == b, so double
			}
			return this.curve.getInfinity(); // this = -b, so infinity
		}

		var THREE = new BI("3");
		var x1 = toBigInteger(this.x);
		var y1 = toBigInteger(this.y);
		var x2 = toBigInteger(b.x);
		var y2 = toBigInteger(b.y);

		var v2 = v.square();
		var v3 = v2.multiply(v);
		var x1v2 = x1.multiply(v2);
		var zu2 = u.square().multiply(this.z);

		// x3 = v * (z2 * (z1 * u^2 - 2 * x1 * v^2) - v^3)
		var x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.q);
		// y3 = z2 * (3 * x1 * u * v^2 - y1 * v^3 - z1 * u^3) + u * v^3
		var y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z)
				.add(u.multiply(v3)).mod(this.curve.q);
		// z3 = v^3 * z1 * z2
		var z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.q);

		return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
	}

	function pointFpTwice() {
		if (this.isInfinity())
			return this;
		if (this.y.toBigInteger().signum() == 0)
			return this.curve.getInfinity();

		// TODO: optimized handling of constants
		var THREE = new BI("3");
		var x1 = this.x.toBigInteger();
		var y1 = this.y.toBigInteger();

		var y1z1 = y1.multiply(this.z);
		var y1sqz1 = y1z1.multiply(y1).mod(this.curve.q);
		var a = this.curve.a.toBigInteger();

		// w = 3 * x1^2 + a * z1^2
		var w = x1.square().multiply(THREE);
		if (!BI.ZERO.equals(a)) {
			w = w.add(this.z.square().multiply(a));
		}
		w = w.mod(this.curve.q);
		// this.curve.reduce(w);
		// x3 = 2 * y1 * z1 * (w^2 - 8 * x1 * y1^2 * z1)
		var x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.q);
		// y3 = 4 * y1^2 * z1 * (3 * w * x1 - 2 * y1^2 * z1) - w^3
		var y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(
				w.square().multiply(w)).mod(this.curve.q);
		// z3 = 8 * (y1 * z1)^3
		var z3 = y1z1.square().multiply(y1z1).shiftLeft(3).mod(this.curve.q);

		return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
	}

	// Simple NAF (Non-Adjacent Form) multiplication algorithm
	// TODO: modularize the multiplication algorithm
	function pointFpMultiply(k) {
		if (this.isInfinity())
			return this;
		if (k.signum() == 0)
			return this.curve.getInfinity();

		var e = k;
		var h = e.multiply(new BI("3"));
		var neg = this.negate();
		var R = this;
		var i;
		for (i = h.bitLength() - 2; i > 0; --i) {
			R = R.twice();

			var hBit = h.testBit(i);
			var eBit = e.testBit(i);

			if (hBit != eBit) {
				R = R.add(hBit ? this : neg);
			}
		}

		return R;
	}

	// Compute this*j + x*k (simultaneous multiplication)
	function pointFpMultiplyTwo(j, x, k) {
		var i;
		if (j.bitLength() > k.bitLength())
			i = j.bitLength() - 1;
		else
			i = k.bitLength() - 1;

		var R = this.curve.getInfinity();
		var both = this.add(x);
		while (i >= 0) {
			R = R.twice();
			if (j.testBit(i)) {
				if (k.testBit(i)) {
					R = R.add(both);
				} else {
					R = R.add(this);
				}
			} else {
				if (k.testBit(i)) {
					R = R.add(x);
				}
			}
			--i;
		}

		return R;
	}

	// 数组合并
	function concatArrays(bin, bin2, bin3) {
		var r = [].concat(bin, bin2);
		if (bin3)
			return r.concat(bin3);
		return r;
	}
	function randomKey() {
		var r = new BI(N.bitLength(), rng);
		return r.mod(N.subtract(ONE)).add(ONE);
	}

	ECPointFp.prototype.getX = pointFpGetX;
	ECPointFp.prototype.getY = pointFpGetY;
	ECPointFp.prototype.equals = pointFpEquals;
	ECPointFp.prototype.isInfinity = pointFpIsInfinity;

	// ----------------
	// ECCurveFp
	// 大整数
	function bn(hexStr) {
		hexStr = hexStr.replace(/\s+/g, "");
		// //console.log("s:" + hexStr);
		return new BI(hexStr, 16);
	}

	function bi2HexStr(tmp) {
		return tmp.toBigInteger().toString(16);
	}

	// constructor
	function ECCurveFp(q, a, b) {
		this.q = q;
		this.a = this.fromBigInteger(a);
		this.b = this.fromBigInteger(b);
		this.infinity = new ECPointFp(this, null, null);
		this.reducer = new Barrett(this.q);
	}

	function curveFpGetQ() {
		return this.q;
	}

	function curveFpGetA() {
		return this.a;
	}

	function curveFpGetB() {
		return this.b;
	}

	function curveFpEquals(other) {
		if (other == this)
			return true;
		return (this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b));
	}

	function curveFpGetInfinity() {
		return this.infinity;
	}

	function curveFpFromBigInteger(x) {
		return new ECFieldElementFp(this.q, x);
	}

	function curveReduce(x) {
		this.reducer.reduce(x);
	}

	var ONE = BI.ONE;
	var N = bn(strN);
	var rng = new SecureRandom();

	ECPointFp.prototype.negate = pointFpNegate;
	ECPointFp.prototype.add = pointFpAdd;
	ECPointFp.prototype.twice = pointFpTwice;
	ECPointFp.prototype.multiply = pointFpMultiply;
	ECPointFp.prototype.multiplyTwo = pointFpMultiplyTwo;

	// for now, work with hex strings because they're easier in JS
	function curveFpDecodePointHex(s) {
		switch (parseInt(s.substr(0, 2), 16)) { // first byte
		case 0:
			return this.infinity;
		case 2:
		case 3:
			// point compression not supported yet
			return null;
		case 4:
		case 6:
		case 7:
			var len = (s.length - 2) / 2;
			var xHex = s.substr(2, len);
			var yHex = s.substr(len + 2, len);

			return new ECPointFp(this, this.fromBigInteger(new BI(xHex, 16)), this.fromBigInteger(new BI(yHex, 16)));

		default: // unsupported
			return null;
		}
	}

	// 密钥派生函数
	function kdf(c2bytes, klen) {
		var n = mathFloor(klen / HASH_BITS); // HASH_BITS:32 整数倍
		var m = klen % HASH_BITS;
		var c2length = c2bytes.length;
		var ct = 1;
		var out = emptyArray();
		// console.log("n:" + n + ",m:" + m);
		for (var i = 0; i < n; i++) {// 整除部分内容
			var counter = codeInt2Bytes(ct);// 32bit，4Byte counter
			var tmp = concatArrays(c2bytes, counter);
			var hv = sm3hash(tmp);
			out = concatArrays(out, hv);
			ct++;
		}
		if (abcd && m > 0) {// 字节数不能被整除
			var counter = codeInt2Bytes(ct);// 32bit，4Byte counter
			var tmp = concatArrays(c2bytes, counter);
			// console.log("counter:\n" + Code.bytes2hexStr(tmp, true));
			var hv = sm3hash(tmp);
			var temp = emptyArray();
			for (var i = 0; i < m; i++) {
				temp.push(hv[i]);
			}
			out = concatArrays(out, temp);
		}
		return out;
	}

	function fpMultpty(pG, k) {
		return pG.multiply(k);
	}

	function curveFpEncodePointHex(p) {
		if (p.isInfinity())
			return "00";
		var xHex = bi2HexStr(p.getX());
		var yHex = bi2HexStr(p.getY());
		var oLen = this.getQ().toString(16).length;
		if ((oLen % 2) != 0)
			oLen++;
		while (xHex.length < oLen) {
			xHex = "0" + xHex;
		}
		while (yHex.length < oLen) {
			yHex = "0" + yHex;
		}
		return "04" + xHex + yHex;
	}

	var curve = null;
	var pG = null;
	var pY = null;
	var sm2Encode = function(msg) {
		// 随机数//
		var pC1, pC2;
		var k = randomKey();
		// k =
		// bn("c59bedca25265cb8205862ef9515ff03b4355efa435fcb618decb988166992c9");
		var init = true;
		do {
			pC1 = fpMultpty(pG, k);
			pC2 = fpMultpty(pY, k);
			// TODO:检查C1、C2有效性
			init = false;
		} while (init);

		var C1 = pointToBytes(pC1);
		// console..log("C1:\n" + Code.bytes2hexStr(C1, true));
		// KDF //
		var binMsg = codeStr2Bytes(msg);
		// console..log("msg bytes length:" + binMsg.length);
		var c2bytes = pointToBytes(pC2);
		var t = kdf(c2bytes, binMsg.length);
		// console..log("kdf=>t:\n" + Code.bytes2hexStr(t, true));
		var C2 = xor(binMsg, t);
		// console..log("C2:\n" + Code.bytes2hexStr(C2, true));

		var pC2xBin = codeCopyArrayRange(c2bytes, 0, 32);
		var pC2yBin = codeCopyArrayRange(c2bytes, 32, 64);
		var C3 = sm3hash(concatArrays(pC2xBin, binMsg, pC2yBin));
		// console..log("C3:\n" + Code.bytes2hexStr(C3, true));
		// 合并
		var rst = emptyArray();
		if (RST_TYPE_C1C2C3 == RST_TYPE) {
			rst = concatArrays(C1, C2, C3);
		} else if (RST_TYPE_C1C3C2 == RST_TYPE) {
			rst = concatArrays(C1, C3, C2);
		}
		// console..log(RST_TYPE + ":\n" + Code.bytes2hexStr(rst, true));
		return codeBytes2HexStr(rst);
	};

	/**
	 * 坐标转字节数组
	 *
	 * @returns
	 */
	function pointToBytes(p) {
		var x = bi2HexStr(p.getX());
		var y = bi2HexStr(p.getY());
		x = ldap(x, BITS / 4);
		y = ldap(y, BITS / 4);
		// console..log("x: " + x + ",y: " + y);
		if (x.length > 64 || y.length > 64) {
			p = fpMultpty(p, abcd);
		}
		return concatArrays(codeHexStr2Bytes(x), codeHexStr2Bytes(y));
	}
	// 异或
	function xor(a, p) {
		if (a.length != p.length) {
			// console.log("xor 长度不一样 aLen:" + a.length + ",pLen:" + p.length);
		}
		var s = emptyArray();
		for (var i = 0, j = a.length; i < j; i++) {
			s[i] = (a[i] ^ p[i]);
		}
		return s;
	}

	ECCurveFp.prototype.getQ = curveFpGetQ;
	ECCurveFp.prototype.getA = curveFpGetA;
	ECCurveFp.prototype.getB = curveFpGetB;
	ECCurveFp.prototype.equals = curveFpEquals;
	ECCurveFp.prototype.getInfinity = curveFpGetInfinity;
	ECCurveFp.prototype.fromBigInteger = curveFpFromBigInteger;
	ECCurveFp.prototype.reduce = curveReduce;
	ECCurveFp.prototype.decodePointHex = curveFpDecodePointHex;
	ECCurveFp.prototype.encodePointHex = curveFpEncodePointHex;

	curve = new ECCurveFp(bn(strP), bn(strA), bn(strB));
	pG = new ECPointFp(curve, curve.fromBigInteger(bn(strGx)), curve.fromBigInteger(bn(strGy)));
	pY = new ECPointFp(curve, curve.fromBigInteger(bn(strPx)), curve.fromBigInteger(bn(strPy)));
	/*
	 * 加密方法
	 */
	_Sm2.encode = sm2Encode;
	_Sm2.init = init;

})();




var sm3Salt = 'YTCSII';
var me = {
    /**
     * 三段式加密(国密)
     * SM3+SM4+SM2
     */
    encrypt : function(data, key) {
        if (typeof data != 'string') {
            data = JSON.stringify(data);
        }
        console.log('key\n'+key);
        var m1 = M1(Code.str2bytes(data));
        var m2 = M2();
        var m = M3(m1, m2);
        var r4 = _Sm4.encode(Code.bytes2hexStr(m), Code.str2bytes(key))
        var sm4Encode = Code.bytes2hexStr(r4);
        console.log('sm4\n'+sm4Encode);

        var sm2Encode = _Sm2.encode(key);
        console.log('sm2\n'+sm2Encode);

        var r3 = _Sm3.hash(Code.str2bytes(data + key + sm3Salt));
        var sm3Encode = Code.bytes2hexStr(r3);
        console.log('sm3\n'+sm3Encode);

        // SM3+SM4+SM2
        var result = "#10" + [ sm3Encode, sm4Encode, sm2Encode ].join(String.fromCharCode(29));
        console.log(result);
        return result;
    },
    // SM4解密
    decrypt : function(data, key){
        var encryptData = data.substr(14);
        var confuseStartPos = parseInt(data.substring(3, 5), 16);
        var confuseLen = parseInt(data.substring(5, 7), 16);
        var confuseRule = parseInt(data.substring(7, 8), 16);
        var originalLen = parseInt(data.substring(8, 14), 16);
        var confuseStr = encryptData.substring(confuseStartPos, confuseStartPos + confuseLen);
        var confuseStrLen = confuseStr.length;
        var confuseData = [];
        confuseData.push(encryptData.substring(0, confuseStartPos));
        switch (confuseRule) {
        case 1:
            confuseData.push(confuseStr.charAt(confuseStrLen - 1))
            confuseData.push(confuseStr.substring(1, confuseStrLen - 1));
            confuseData.push(confuseStr.charAt(0));
            break;
        case 2:
            for (var j = 2; j <= confuseStrLen; ++j) {
                if (j % 2 == 0) {
                    confuseData.push(confuseStr.charAt(j - 1));
                    confuseData.push(confuseStr.charAt(j - 2));
                }
            }
            if (confuseStrLen % 2 != 0 && confuseStrLen > 0) {
                confuseData.push(confuseStr.charAt(confuseStrLen - 1));
                break;
            }
            break;
        }
        if (confuseRule != 0) {
            confuseData.push(encryptData.substring(confuseStartPos + confuseLen));
            encryptData = confuseData.join('');
        }
        encryptData = encryptData.substring(0, originalLen);
        console.log('encryptData\n'+encryptData);
        console.log('key\n'+key);
        var result = _Sm4.crypt(Code.hexStr2bytes(encryptData), Code.str2bytes(key), 0);
        return byteToString(result);
    },

    getEncryptKey : function() {
        return me.uuid(32, 16);
    },
    uuid : function(len, radix) {
        var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('');
        var uuid = [], i;
        radix = radix || chars.length;
        if (len) {
            // Compact form
            for (i = 0; i < len; i++)
                uuid[i] = chars[0 | Math.random() * radix];
        } else {
            // rfc4122, version 4 form
            var r;
            // rfc4122 requires these characters
            uuid[8] = uuid[13] = uuid[18] = uuid[23] = '-';
            uuid[14] = '4';
            // Fill in random data. At i==19 set the high bits of
            // clock
            // sequence
            // as
            // per rfc4122, sec. 4.1.5
            for (i = 0; i < 36; i++) {
                if (!uuid[i]) {
                    r = 0 | Math.random() * 16;
                    uuid[i] = chars[(i == 19) ? (r & 0x3) | 0x8 : r];
                }
            }
        }
        return uuid.join('');
    }
}
function M1(datas){
    var length = datas.length;
    var size = length % 16;
    size = 16 - size;
    var tmp = new Array();
    tmp[0] = 29;
    for (var i = 1; i < size; i++) {
        tmp[i] = Math.round(Math.random() * 150) % 150 + 30;
    }
    var l = size + length;
    var out = new Array();
    out = [].concat(datas);
    for(var i = 0; i < tmp.length; i++){
        if(i < size){
            out.push(tmp[i])
        }
    }
    return out;
}
function M3(m1, m2){
    var lenM1 = m1.length;
    var lenM2 = m2.length;
    var out = new Array();
    var m3 = xor(m1, m2);
    for(var i = 0; i < m3.length; i++){
        if(i < lenM1){
            out.push(m3[i])
        }
    }
    for(var i = 0; i < m2.length; i++){
        if(i < lenM2){
            out.push(m2[i])
        }
    }
    return out;
}
function xor(m1, m2){
    var lenM1 = m1.length;
    var m3 = new Array();
    var s1 = lenM1 / 16;
    for (var a = 0; a < s1; a++) {
        var index = a * 16;
        for (var i = 0; i < 16; i++) {
            m3[index + i] =  (m1[index + i] ^ m2[i]);
        }
    }
    return m3;
}
function M2(datas){
    var tmp = new Array();
    for (var i = 0; i < 16; i++) {
        tmp[i] = Math.round(Math.random() * 255) % 255;
    }
    return tmp;
}
function byteToString(arr) {
    if(typeof arr === 'string') {
        return arr;
    }
    var str = '',
        _arr = arr;
    for(var i = 0; i < _arr.length; i++) {
        var one = _arr[i].toString(2),
            v = one.match(/^1+?(?=0)/);
        if(v && one.length == 8) {
            var bytesLength = v[0].length;
            var store = _arr[i].toString(2).slice(7 - bytesLength);
            for(var st = 1; st < bytesLength; st++) {
                //store += _arr[st + i].toString(2).slice(2);
                if (_arr[st+i]){
                store += _arr[st + i].toString(2).slice(2);}
            }
            str += String.fromCharCode(parseInt(store, 2));
            i += bytesLength - 1;
        } else {
            str += String.fromCharCode(_arr[i]);
        }
    }
    return str;
}


function jiami(data,keey){

var result=me.encrypt(data,keey)
console.log("chenggong:")
return result

}
function jiemi(data,keyss){
var jieguo=me.decrypt(data,keyss);
return jieguo;
}

