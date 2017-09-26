Chris Kuffert : kuffert
Arjun Rao : arao
Group : charjun

12/9/16 

Overview ------

Overall, project 5 was a challenge, but was a welcomed change of pace from programming raw sockets in project 4.
The DNS took the majority of the time, ~45 hours or so, with the http server coming in at ~15. After these
two bases were done, with the DNS returning the first origin IP and the http fetching content, we moved into
optimization and efficiency improvements, which I will discuss below, along with challenges we faced. 

We decided for the sake of consistency to remain using C++ to program this project, as it has been what we've
used since the start. We both wanted to gain a better understanding of the language this semester, and while it 
has caused us substantial frustration at times, we figured we would be better off  sticking with this language. 

High level approach ----------

Our goal from the beginning was as follows: 

1. get the DNS working on a local machine, returning a single replica IP.
2. get the http server working on a local machine, returning data from the origin (no caching)
3. implement caching on the http server, and only fetch content from the origin if it is not cached
4. optimize caching to track commonly requested files/ remove infrequent files, dynamically adjust cache when
10MB max is reached, and manage cache during downtime (no incoming requests)
5. implement geoip for improved DNS responses
6. construct deploy, run, and stop scripts for replica servers
7. test dns and http servers on one replica with local digs and wgets
8. test dns and http servers on all replicas with local digs and wgets 
9. iterate upon design to improve efficiency 

This was our plan, and we followed it the whole way through. Getting to step 3 by the end of thanksgiving break
gave us a lot of time to work on the remaining features. Thankfully so, as we ran into some trouble getting the
deployment scripts working, which took a few TA visits to resolve. But with those issues fixed, we had the CDN
working on our local machines, on the first instance of the replicas, and on all the replicas by the weekend of 
12/2, which was excellent. We were able to use the time between then and the final exam to study. The only 
deviation we made from our high level plan was that we delayed implementing geoip functionality until after 
the final exam. But thankfully, all of the functionality we outline was completed. 

Writing this on the day of submission, the only thing we could have used more time for would be to continue 
iterating on our desing, to improve the efficiency of our http and dns server response times. As of now, the DNS
response times are very quick, and the http is great when pages are cached, and decent when content needs to
be fetched from the origin. We are happy with where we are at, and though we may not excel when compared to
other students, we will be satisfied however we rank. 


DNS server --------- 
The DNS server, at startup, will request geographic locations of all replica server IP addresses and store them,
then enter a receiving loop and await DNS lookup requests. When it receives a lookup request, it will first 
verify that the query parameter of the lookup request matches the -n name parameter of the dns server. If it 
does, an answer packet is constructed, in which the client's IP geographic address is ranked based on distance
to each of the cached replica server geographic locations. This "best" IP is placed into the answer packet, and
sent back to the querying client. Should the client request a query that is not supported by our domain, we
will respond with their query packet, with the NXDOMAIN flag set. 


DNS challenges -------
The DNS was a doozy, primarily because forming the packet took significant time digging through wireshark to 
get correct. It took an unequivocal amount of time compared to the rest of the project, but most issues were
tied to C++ type mismatches, bit stuffing and other miscellaneous issues. 


HTTP server -------- 
The http server starts with an empty cache, and clears its cache upon close. It currently only use a RAM cache,
and not a disk cache (With more time we would likely have implemented a disk cache as well). When the server 
recieves a wget request, it first checks its cache, implemented as a map of <string, string> key/value pairs, 
and determines if it already contains the requested file. If it does, then it simply sends the contents back to
the requester, and increments the number of hits that that file has gotten. If it does not have the contents, it
fetches it from the origin, sends the content to the client, and then caches it in memory. We perform the cache
filling after we send the content, to improve efficiency. If the cache is full, the cache will perform a cleanup,
in which it recursively decreases the number of hits on all content in the cache until once reaches 0 hits. That
content is then removed, and the new content is stored. If the old content's removal did not free enough memory,
then the cache will continue to recur, until enough space has been made for the new content. In its downtime, 
when no requests are being received, the http server will periodically optimize its cache by updating the hits
on each item within it. These decisions were made in order to improve the efficiency of a recursive cache purge.


HTTP challenges ------ 
We did not face too many challenges with http implemention, as we utilized functionality from project 2. 
Evaluation of efficiency proved to be slightly challenging, and while the system could be further optimized
(increasing cache size by utilizing disk space, perform background cache management more/less frequently, etc),
we are satisfied with its current capability. 

Thank you!







