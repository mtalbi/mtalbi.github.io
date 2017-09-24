---
layout: default
title: Posts
---

<div class="home">

  <ul class="post-list">
    {% for post in site.posts %}
      <li>
        {% assign date_format = site.minima.date_format | default: "%b %-d, %Y" %}
        <p><a href="{{ post.url | relative_url }}">{{ post.title | escape }}</a> - {{ post.date | date: date_format }}</p>
      </li>
      {{ post.excerpt }} 
    {% endfor %}
  </ul>

</div>
