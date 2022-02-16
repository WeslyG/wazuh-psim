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
#include <stdbool.h>

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
  char user[50];
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
    mdebug1 ("start parse_point");
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
    mdebug1 ("end parse_point");
    mdebug1("result.x = %lf", result.x);
    mdebug1("result.y = %lf", result.y);
    return result;
}


int parse_point_arr(char *input_data, struct Point *room) {
  // char rule_input_data[]= "1,2.666;7.823,99.22;3.2,1.1;4.22,2.7;4.78,2.7;-142.583,999";
  struct Point current_point;

  int len = strlen(input_data);
  int switcher = 1;
  int state = 0;
  int roomCount = 0;
  struct Point tempPoint;

  mdebug1("input = %s", input_data);

  for (int i = 0; i <= len; i++) {
    if (input_data[i] == ',' || input_data[i] == ';' || i == len) {
      int q = i - state;
      char tempStr[50] = "";
      strncpy(tempStr, &input_data[state], q);

      // printf("tmpstr = %s\n", tempStr);
      if (switcher % 2 != 0) {
        tempPoint.x = atof(tempStr);
      } else {
        tempPoint.y = atof(tempStr);
        room[roomCount] = tempPoint;
        roomCount++;
        memset(&tempPoint, 0, sizeof(tempPoint));
      }
      switcher++;
      state = i + 1;
    }
  }
  return 0;
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
    OS_XML xml;
    XML_NODE node;
    bool result = false;
    struct PsimConfig config[100] = {0};
    char *psim_config = "etc/psim.xml";
    
    mdebug1 ("Start decoder");
    mdebug1("config read start");
    if (OS_ReadXML(psim_config, &xml) < 0) {
        merror(XML_ERROR, psim_config, xml.err, xml.err_line);
        return (OS_INVALID);
    }
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        mdebug1 ("!node");
        return (0);
    }
    mdebug1 ("config read end");

    if (!node[0]->element) {
      mdebug1 ("Not rules in xml!");
      merror(XML_ELEMNULL);
      OS_ClearNode(node);
      OS_ClearXML(&xml);
      return (OS_INVALID);
    }

    int i = 0;
    while(node[i]) {
      
      if (strcmp(node[i]->element, "rule") == 0) {
          XML_NODE chld_node = NULL;
          chld_node = OS_GetElementsbyNode(&xml, node[i]);

          // Парсим юзера, копируем в конфигу
          if (strcmp(chld_node[0]->element, "user") == 0) {
            strncpy(config[i].user, chld_node[0]->content, strlen(chld_node[0]->content));
          } else {
            mdebug1("First node must be a <user>");
          }

          // Парсим комнату, копируем в конфигу
          if (strcmp(chld_node[1]->element, "room") == 0) {
            if (!parse_point_arr(chld_node[1]->content, config[i].room) == 0) {
              mdebug1("ERROR with parsing room data");
            } else {
              mdebug1("Parsing room data fine");
            }
          } else {
            mdebug1("Second node must be a <room>");
          }
          OS_ClearNode(chld_node);
      } else {
        mdebug1("Psim.xml root node must be a <rule>");
      }
      i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

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
    mdebug1 ("User complite find = %s", user);

    // Current point
    char *point_exist = strstr(lf->full_log,"point=\"");
    if (point_exist == NULL) {
      mdebug1 ("Point error");
      return (NULL);
    }
    mdebug1 ("Start parse point");
    struct Point current_point = parse_point(point_exist);
    mdebug1 ("Current point parsed");

    // Бежим по конфиге, и ищем юзера
    // Если нашли, берем его комнату, и запихиваем в room
    // И считаем result от нашего правила
    int config_size = sizeof(config)/sizeof(config[0]);
    for (int i = 0; i < config_size; i++) {
      // mdebug1 ("start loop");
      if (strcmp(config[i].user,user) == 0) {
        mdebug1 ("user match = %s", config[i].user);
        int n = sizeof(config[i].room) / sizeof(config[i].room[0]);
        
        mdebug1 ("XXX.0 = %lf", config[i].room[0].x);
        mdebug1 ("YYY.0 = %lf", config[i].room[0].y);

        mdebug1 ("XXX.1 = %lf", config[i].room[1].x);
        mdebug1 ("YYY.1 = %lf", config[i].room[1].y);

        mdebug1 ("XXX.2 = %lf", config[i].room[2].x);
        mdebug1 ("YYY.2 = %lf", config[i].room[2].y);

        mdebug1 ("XXX.3 = %lf", config[i].room[3].x);
        mdebug1 ("YYY.3 = %lf", config[i].room[3].y);

        result = isInside(config[i].room, n, current_point);
        mdebug1 ("result = %s", result ? "true" : "false");
        // Запихиваем результат в action, если есть совпадение
        if (result == true) {
          mdebug1 ("result was writen in action");
          os_strdup("true", lf->action);
          os_strdup(user, lf->dstuser);
          
          char *ress = (char*)malloc(sizeof(current_point.x) + sizeof(current_point.y) * sizeof(double));
          sprintf(ress, "alert point is x=%lf, y=%lf", current_point.x, current_point.y);
          os_strdup(ress, lf->extra_data);
          free(ress);
        }
      } else {
        // Else бежим по всем остальным правилам
        // mdebug1 ("continue");
        continue;
      }
    }
    mdebug1 ("finish");
    result = false;
    // free(user);
    // free(user_exist);
    // free(config_size);
    // free(config);
    // free(node);
    // free(point_exist);
    return (NULL);
}

// os_strdup("result", lf->fields[].key);
// os_strdup("true", lf->fields[].value);