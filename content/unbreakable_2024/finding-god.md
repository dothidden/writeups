---
title: finding-god
type: writeup
date: 2024-04-07T13:45:05+03:00
description: Writeup for finding-god [Unbreakable 2024]
author: H0N3YP0T
tags:
- osint
draft: false
---
___

## Challenge Description

Find the name of a place of worship located in Italy, beside water and close to hospital,park and a railroad. We checked on OSM, and there is only one.

Flag format is CTF{sha256(Location Name)}.

EX: CTF{sha256("Parrocchia S. Teresa di Gesù Bambino")}


## Intuition

Since the challenge mentioned OSM (OpenStreetMap), we knew we had to use OSM queries to find the location. Therefore, our 
first choice went to [overpass-turbo](https://overpass-turbo.eu/) and we started building queries to find the location.

```sql
[out:json][timeout:800];
{{geocodeArea:Italy}}->.searchArea;
// gather results 
(
  nwr(area.searchArea)["amenity"="place_of_worship"];
 )->.worship;

(
  nwr(around.worship:250)["amenity"="hospital"];
)->.hospital;

(
  node.worship(around.hospital:250);
  way.worship(around.hospital:250);
  relation.worship(around.hospital:250);
)->.matching_1;

(
  nwr(around.matching_1:250)["natural"="water"];
)->.water;

(
  node.matching_1(around.water:250);
  way.matching_1(around.water:250);
  relation.matching_1(around.water:250);
)->.matching_2;

(
  nwr(around.matching_2:250)["leisure"="park"];
)->.park;

(
  node.matching_2(around.park:250);
  way.matching_2(around.park:250);
  relation.matching_2(around.park:250);
)->.matching_3;


(
  nwr(around.matching_3:250)["railway"="rail"];
)->.rail;



(
  node.matching_3(around.rail:250);
  way.matching_3(around.rail:250);
  relation.matching_3(around.rail:250);
)->.matching_worship;


(.matching_worship;);

// print results
out geom;
```
Unfortunately this query timed out such as all the other queries we tried. We started to suffer from severe depression after working for more than 2 days on it.

## Solution

Being in depression I started to look at other possible tools to find the location. I found the following [tool](https://osm-search.bellingcat.com/) and
noticed it uses the exact same filter as in the description. 

![img.png](/images/unbreakable_2024/map.png)

Unfortunately after scanning all over Italy, I found many different places and by some miracle I understood I had to put the 
filter in the same order as the description. `Church`, `Water`, `Hospital`, `Park` and `Railroad`. After scanning again all over
Italy I found only one location in Roma.

![img.png](/images/unbreakable_2024/god.png)
![img.png](/images/unbreakable_2024/church.png)

The last step is to input `Oratorio di Santa Maria Annunziata` in a SHA256 hash generator and get the flag.

After some pray, god found us.

### Flag

`CTF{be353ec1796c6c5e5d99e31fa14ce0458977d329a0e97356622fdaf80722d7cd}`

### Acknowledge

This writeup was co-authored by [sunbather](https://github.com/costinteo) becoming joker with me.

![200w.webp](/images/unbreakable_2024/joker.webp)
