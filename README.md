# Udacity CS253: Web Applicartion Tutorial

Here are the source codes for web applications I am building through this course.

##Problem Statement 1: Date Validation
It is fricking obvious that a date has a day, a month and a year but, each of these parameters need separate validation logic. It's pretty strange american way of formatting a date is different from rest of the world. But I find it cool that they get a PI day on 14th of March (3/14).

![Pi Day GIF](http://i.giphy.com/ZGc7iOdkmloOc.gif)

###Validating Month
```python
def valid_month(month):
    if month:
        short_month = month[:3].lower()
        return month_abbvs.get(short_month)
```

###Validating Day
```python
def valid_day(day):
    if day and day.isdigit():
        day = int(day)
        if day > 0 and day <=31:
            return day
  ```
  
###Validating Year
  ```python
  def valid_year(year):
    if year and year.isdigit():
        year = int(year)
        if year > 1993 and year <=2020:
            return year
  ```
