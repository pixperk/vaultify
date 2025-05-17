-- KEYS[1] = Redis key for the client's token bucket
-- ARGV[1] = max tokens (bucket capacity)
-- ARGV[2] = refill rate (tokens per second)
-- ARGV[3] = current timestamp (in seconds)

-- 1. Fetch current token count and last refill time:
local bucket = redis.call("HMGET", KEYS[1], "tokens", "last")
local tokens = tonumber(bucket[1]) or ARGV[1]
local last = tonumber(bucket[2]) or ARGV[3]

-- 2. Calculate elapsed time since the last refill:
local delta = ARGV[3] - last

-- 3. Compute how many tokens to refill:
local refill = delta * ARGV[2]

-- 4. Add the refill tokens to the bucket, but don’t exceed max tokens:
tokens = math.min(tokens + refill, ARGV[1])

-- 5. Check if there’s at least one token available:
if tokens < 1 then
  return -1  -- Signal to block the request.
end

-- 6. Deduct one token for the current request:
tokens = tokens - 1

-- 7. Save the updated token count and current timestamp:
redis.call("HMSET", KEYS[1], "tokens", tokens, "last", ARGV[3])

-- 8. Set an expiration on this key:
redis.call("EXPIRE", KEYS[1], 3600)

-- 9. Return the number of tokens remaining:
return tokens
