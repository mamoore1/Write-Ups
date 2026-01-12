# Impossible Travel with Splunk (and some KQL)

So as part of an attempt to get some general hands-on experience, I have previously set up a home lab with the following components using Oracle Virtualbox:

- Windows 2022 Server (DC) (VM)
- Windows 11 Enterprise Client (VM)
- Splunk Enterprise (Free) (Running with Ubuntu)

The idea being that I can run some Atomic Red Team tests or manually test exploits and then practice investigating in the Splunk logs.

This is my first attempt at doing this manually, and, to start simple (famous last words), I decided to do an impossible travel test.

## What is impossible travel?

Impossible travel is a security incident where a user logs in from 2 different locations in a time frame where it is not possible that they could have travelled from A to B in that time frame. For instance, imagine that I am detected logging in to my work computer in the UK, then 30 minutes later I am detected logging into my computer using remote desktop in Australia. Within 30 minutes, I cannot possibly have travelled to Australia, so something odd is going on here. Now, it's possible that I've logged in from the UK, then loaded up a VPN, switched my location to Australia to watch something on Netflix (Neighbours? What else is out there in Australia?), and then logged into my work account again. Ignoring the question of why I'm watching Netflix at work, this is not a cybersecurity incident (it may, however, be an HR incident!)

Contrast with the case where I log in from the UK, then 2 days later log-in from Australia. This could be legitimate; I may have travelled for work (or may be on holiday checking emails). This is probably still deserving of a follow-up, but is not obviously problematic.

## So, what's the plan?

The idea is:

1. Generate some logins from both the UK and Australia 30 minutes or so apart
2. Write an SPL search that will find instances of this kind of impossible travel
3. Check that the search correctly finds the event but does not capture instances of possible travel

## Getting started

People who have thought further ahead than I did will have noticed that I can't really simulate impossible travel on a home lab that is located on one laptop with no internet connection. Unfortunately, I did not think that far ahead. This is where my good friend Claude steps in to help me generate some alerts. To do this, I took an existing login event from my logs, and uploaded it to Claude, asking it to generate 2 RDP login events (i.e., LogonType 10), one from the UK and one from Australia.

![Original event, dumped from Splunk](https://github.com/user-attachments/assets/a22e424a-c237-4b1e-a691-debebe587dfd)
*Original event, dumped from Splunk*

![New events created](https://github.com/user-attachments/assets/a399afea-2255-4550-a99a-a2b9be182a90)
*New events created*

From the main page I then went to Settings -> Add Data -> Upload and uploaded the CSV file. Splunk set the sourcetype to csv, so going forward I'll be using `(sourcetype="WinEventLog:Security" OR sourcetype="csv")` to show both datasets.

<img width="1832" height="453" alt="image4" src="https://github.com/user-attachments/assets/ef280961-7347-499a-9f9a-e31c3d98cec5" />

## Next step: querying for impossible travel

Now, part of the reason I wanted to do Impossible Travel as a first detection is that I thought it was going to be (relatively) easy. I have more familiarity with Windows Analytics Logs and KQL, and in KQL you can use functions like [geo_info_from_ip_address](https://learn.microsoft.com/en-us/kusto/query/geo-info-from-ip-address-function?view=microsoft-fabric) and [geo_distance_2points](https://learn.microsoft.com/en-us/kusto/query/geo-distance-2points-function?view=microsoft-fabric) to determine the distances. It turns out this is more complicated in SPL.

### The KQL approach

For starters, let's figure this out for KQL. We know that we're looking for WinEvent:Security logs (in the `SecurityEvent` table for Sentinel), and for simplicity we're assuming we only care about RDP remote logins. We'll be looking for logins to the same account from different IP addresses and we'll do this by pairing up all the logins (by joining on the same table) where the second login is after the first login (ignoring matching IP addresses). So:

```kql
SecurityEvent
| where EventID == 4624 and LogonType == 10
| distinct TimeGenerated, TargetUserName, IpAddress
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and LogonType == 10
    | distinct TimeGenerated, TargetUserName, IpAddress
) on TargetUserName
| where TimeGenerated < TimeGenerated1
| where IpAddress != IpAddress1
```

Next, we want to use `geo_info_from_ip_address` to get the, well, geo info.

```kql
| extend geo = geo_info_from_ip_address(IpAddress), geo1 = geo_info_from_ip_address(IpAddress1)
```

`geo_info_from_ip_address` gives us a bunch of different information, but what we're interested in is "longitude" and "latitude", as those are the inputs to `geo_distance_2points`. So:

```kql
| extend DistanceKm = geo_distance_2points(geo.longitude, geo.latitude, geo1.longitude, geo1.latitude) / 1000
// function provides distance in meters
```

Now, we want to determine a) the time it took to travel between the two logins and b) the travel speed. We'll then check whether the travel speed is under a suitable threshold. A quick google suggested that 1000km/h is a decent threshold (as apparently planes often travel at 900km/h), so we'll go with that.

```kql
| extend TravelTimeHours = (TimeGenerated1 - TimeGenerated) / 1h
// dividing by 1h to convert from a 'timespan' into hours
| extend TravelSpeedKmh = DistanceKm / TravelTimeHours
| where TravelSpeedKmh > 1000
| project TimeGenerated, TimeGenerated1, TargetUserName, IpAddress, IpAddress1, TravelSpeedKmh, DistanceKm
```

So this should give us our alerts, in Sentinel anyway (I don't have Sentinel set up to test this, so treat this as pseudocode rather than production ready!).

### Rewriting in SPL

So, now we just need to rewrite this in SPL. This is going to start out fairly simple. To get the relevant login pairs (remembering that we need to include `sourcetype=csv` to get our example events):

```spl
index="main" (sourcetype="WinEventLog:Security" OR sourcetype="csv") EventCode="4624" Logon_Type=10
| dedup _time, Account_Name, Source_Network_Address
| fields _time, Account_Name, Source_Network_Address
| join type=inner max=0 Account_Name [
    search index="main" (sourcetype="WinEventLog:Security" OR sourcetype="csv") EventCode="4624" Logon_Type=10
    | dedup _time, Account_Name, Source_Network_Address
    | fields _time, Account_Name, Source_Network_Address
    | rename _time as time1, Source_Network_Address as src_ip1
]
| where _time < time1 AND Source_Network_Address != src_ip1
```

This is simple enough; it's mostly the same, although we need to add in `max=0` because by default SPL only matches each main search result to 1 subsearch result. Also, Splunk doesn't like it when custom fields start with underscores, so we renamed `_time` from the subsearch to `time1`. The query so far gives us basically what we would expect, which is a bunch of different pairs of login events (once again, my great research assistant Claude helped generate a bunch more LogonType 10 events).

<img width="1013" height="562" alt="image2" src="https://github.com/user-attachments/assets/cfc48bd5-fb1e-41f4-95f2-7d3e5282c3b6" />

Now we need to narrow this down to just those pairs where impossible travel is happening. We can get location information using [iplocation](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.3/search-commands/iplocation):

```spl
| iplocation Source_Network_Address
| iplocation prefix=dest_ src_ip1
```

Similarly to `geo_info_from_ip_address`, this gives us a bunch of other information, but we just need `lat`, `lon`, `dest_lat` and `dest_lon`. Now, this is where it gets tricky (or fun, depending on the kind of person you are). SPL does not have built-in support for distances between geocoordinates. Instead, we're going to have to write our own (we could install a Splunk app to do it for us, but where's the fun in that?)

### The Haversine formula

To calculate the distance between two points on the earth's surface, we use something called the [Haversine formula](https://en.wikipedia.org/wiki/Haversine_formula), which calculates the shortest distance over the Earth's surface. At times like this I wish I'd paid better attention in maths class (and probably learned LaTeX), but it looks like this:

```
a = sin²(Δφ/2) + cos φ1 ⋅ cos φ2 ⋅ sin²(Δλ/2)
c = 2 ⋅ atan2( √a, √(1−a) )
d = R ⋅ c
```

Where φ (phi) is the latitude in radians, λ (lambda) is the longitude, and R is the earth's radius.

First we convert `lat`, `lon`, `dest_lat` and `dest_lon` into radians:

```spl
| eval lat = pi() * lat / 180, dest_lat = pi() * dest_lat / 180, lon = pi() * lon / 180, dest_lon = pi() * dest_lon / 180
```

Then we do the Haversine formula:

```spl
| eval delta_lat = dest_lat - lat
| eval delta_lon = dest_lon - lon
| eval a = sin(delta_lat / 2) * sin(delta_lat / 2) + cos(lat) * cos(dest_lat) * sin(delta_lon / 2) * sin(delta_lon / 2)
| eval c = 2 * atan2(sqrt(a), sqrt(1-a))
| eval Distance = 6371 * c
```

Which gives us the distance in kilometres. Now, we can apply our filtering, noting that `time1 - _time` will be in seconds:

```spl
| eval TravelTimeHours = (time1 - _time) / 3600
| eval TravelSpeedKmh = Distance / TravelTimeHours
| where TravelSpeedKmh > 1000
```

And this gives us the expected single result!
<img width="1338" height="134" alt="image6" src="https://github.com/user-attachments/assets/cd79566c-316b-4765-9922-5f64a1d41eaa" />

### The full KQL query (untested!)

```kql
SecurityEvent
| where EventID == 4624 and LogonType == 10
| distinct TimeGenerated, TargetUserName, IpAddress
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and LogonType == 10
    | distinct TimeGenerated, TargetUserName, IpAddress
) on TargetUserName
| where TimeGenerated < TimeGenerated1
| where IpAddress != IpAddress1
| extend geo = geo_info_from_ip_address(IpAddress), geo1 = geo_info_from_ip_address(IpAddress1)
| extend DistanceKm = geo_distance_2points(geo.longitude, geo.latitude, geo1.longitude, geo1.latitude) / 1000
| extend TravelTimeHours = (TimeGenerated1 - TimeGenerated) / 1h
| extend TravelSpeedKmh = DistanceKm / TravelTimeHours
| where TravelSpeedKmh > 1000
| project TimeGenerated, TimeGenerated1, TargetUserName, IpAddress, IpAddress1, TravelSpeedKmh, DistanceKm
```

### The full SPL query

```spl
index="main" (sourcetype="WinEventLog:Security" OR sourcetype="csv") EventCode="4624" Logon_Type=10
| dedup _time, Account_Name, Source_Network_Address
| fields _time, Account_Name, Source_Network_Address
| join type=inner max=0 Account_Name [
    search index="main" (sourcetype="WinEventLog:Security" OR sourcetype="csv") EventCode="4624" Logon_Type=10
    | dedup _time, Account_Name, Source_Network_Address
    | fields _time, Account_Name, Source_Network_Address
    | rename _time as time1, Source_Network_Address as src_ip1
]
| where _time < time1
| where Source_Network_Address != src_ip1
| iplocation Source_Network_Address
| iplocation prefix=dest_ src_ip1
| eval lat = pi() * lat / 180, dest_lat = pi() * dest_lat / 180, lon = pi() * lon / 180, dest_lon = pi() * dest_lon / 180
| eval delta_lat = dest_lat - lat
| eval delta_lon = dest_lon - lon
| eval a = sin(delta_lat / 2) * sin(delta_lat / 2) + cos(lat) * cos(dest_lat) * sin(delta_lon / 2) * sin(delta_lon / 2)
| eval c = 2 * atan2(sqrt(a), sqrt(1-a))
| eval Distance = 6371 * c
| eval TravelTimeHours = (time1 - _time) / 3600
| eval TravelSpeedKmh = Distance / TravelTimeHours
| where TravelSpeedKmh > 1000
```

## Conclusion

So there we have it: an SPL detection for impossible travel, a bit of KQL, and an unexpected lesson in the Haversine formula!
