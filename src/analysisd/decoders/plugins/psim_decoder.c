/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../plugin_decoders.h"

#include "shared.h"
#include "eventinfo.h"


#include <stdio.h>
#include <stdlib.h>
#include<stdbool.h>

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#define INF 10000

struct Point
{
  double x;
  double y;
};

struct PsimConfig
{
  char *user;
  struct Point room[100];
};

bool onSegment(struct Point p, struct Point q, struct Point r)
{
  if (q.x <= max(p.x, r.x) && q.x >= min(p.x, r.x) &&
      q.y <= max(p.y, r.y) && q.y >= min(p.y, r.y))
    return true;
  return false;
}

int orientation(struct Point p, struct Point q, struct Point r)
{
  int val = (q.y - p.y) * (r.x - q.x) -
            (q.x - p.x) * (r.y - q.y);

  if (val == 0)
    return 0;               // collinear
  return (val > 0) ? 1 : 2; // clock or counterclock wise
}

bool doIntersect(struct Point p1, struct Point q1, struct Point p2, struct Point q2)
{
  // Find the four orientations needed for general and
  // special cases
  int o1 = orientation(p1, q1, p2);
  int o2 = orientation(p1, q1, q2);
  int o3 = orientation(p2, q2, p1);
  int o4 = orientation(p2, q2, q1);

  // General case
  if (o1 != o2 && o3 != o4)
    return true;

  // Special Cases
  // p1, q1 and p2 are collinear and p2 lies on segment p1q1
  if (o1 == 0 && onSegment(p1, p2, q1))
    return true;

  // p1, q1 and p2 are collinear and q2 lies on segment p1q1
  if (o2 == 0 && onSegment(p1, q2, q1))
    return true;

  // p2, q2 and p1 are collinear and p1 lies on segment p2q2
  if (o3 == 0 && onSegment(p2, p1, q2))
    return true;

  // p2, q2 and q1 are collinear and q1 lies on segment p2q2
  if (o4 == 0 && onSegment(p2, q1, q2))
    return true;

  return false; // Doesn't fall in any of the above cases
}

bool isInside(struct Point polygon[], int n, struct Point p)
{
  // There must be at least 3 vertices in polygon[]
  if (n < 3)
    return false;

  // Create a point for line segment from p to infinite
  struct Point extreme = {INF, p.y};

  // Count intersections of the above line with sides of polygon
  int count = 0, i = 0;
  do
  {
    int next = (i + 1) % n;

    if (doIntersect(polygon[i], polygon[next], p, extreme))
    {
      if (orientation(polygon[i], p, polygon[next]) == 0)
        return onSegment(polygon[i], p, polygon[next]);

      count++;
    }
    i = next;
  } while (i != 0);

  // Return true if count is odd, false otherwise
  return count & 1; // Same as (count%2 == 1)
}


//  * Examples:
//  * point="12.444;-3.04"
struct Point parse_point(char *data)
{
    int length = 0;
    struct Point result;
    char *point = malloc(sizeof(char) * (strlen(data) + 1));

    // 7 = длина константы 'point="'
    for (int i = 7; i < strlen(data); i++) {
      if (data[i] == '"') {
        break;
      }
      if (data[i] == ' ') {
        continue;
      }
      point[length] = data[i];
      length++;
    }
    length = 0;

    for(int i = 0; i < strlen(point); i++) {
      if (point[i] == ';') {
        length = i;
      }
    }

    char x[length+1];
    memset(&x, 0, sizeof(x));
    strncpy(x, &point[0], length);

    int z = strlen(point) - length;
    char y[z];
    memset(&y, 0, sizeof(y));
    strncpy(y, &point[length+1], z);

    result.x = atof(x);
    result.y = atof(y);
    free(point);
    return result;
}


/* PSIM decoder init */
void *PSIM_Decoder_Init()
{
    mdebug1("Initializing PSIM decoder..");

    /* There is nothing to do over here */
    return (NULL);
}

/* PSIM decoder
 * Will return entering a given area
 *
 * Examples:
 * user="petya" point="12.444;-3.04"
 */
void *PSIM_Decoder_Exec(Eventinfo *lf, __attribute__((unused)) regex_matching *decoder_match)
{
    bool result;
    mdebug1 ("Start decoder");
    struct PsimConfig config[] = {
        {
          user: "vasya",
          room: {{0, 0}, {10, 0}, {10, 10}, {0, 10}}
        },
        {
          user: "petya",
          room: {{10, 10}, {20, 10}, {20, 20}, {10, 20}}
        },
      };

    // Current user
    char *user_exist = strstr(lf->full_log,"user=\"");
    if (user_exist == NULL) {
      mdebug1 ("User not exist");
      return (NULL);
    }

    int length = 0;
    char user[50];
    for (int i = 6; i < strlen(user_exist); i++) {
      if (user_exist[i] == '"') {
        break;
      }
      user[length] = user_exist[i];
      length++;
    }
    mdebug1 ("User complite find");
    // printf("%s\n", user);

    // Current point
    char *point_exist = strstr(lf->full_log,"point=\"");
    if (point_exist == NULL) {
      mdebug1 ("Point error");
      return (NULL);
    }
    struct Point current_point = parse_point(point_exist);
    mdebug1 ("Current point");

    // Бежим по конфиге, и ищем юзера
    // Если нашли, берем его комнату, и запихиваем в room
    // И считаем result от нашего правила
    int config_size = sizeof(config)/sizeof(config[0]);
    for (int i = 0; i < config_size; i++) {
      mdebug1 ("start loop");
      mdebug1 ("user = %s", user);
      mdebug1 ("user[i] = %s", config[i].user);
      if (strcmp(config[i].user,user) == 0) {
        mdebug1 ("user match");
        int n = sizeof(config[i].room) / sizeof(config[i].room[0]);
        result = isInside(config[i].room, n, current_point);
        mdebug1 ("result = %s", result ? "true" : "false");
        // Запихиваем результат в action, если есть совпадение
        if (result == true) {
          mdebug1 ("result was writen in action");
          os_strdup("true", lf->action);
        }
      } else {
        // Else бежим по всем остальным правилам
        mdebug1 ("continue");
        continue;
      }
    }
    mdebug1 ("finish");
    return (NULL);
}


// os_strdup("result", lf->fields[].key);
// os_strdup("true", lf->fields[].value);