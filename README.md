# netatmo-trmnl
### plugin configuration
#### strategy
```
polling
```

#### polling url
```
http://netatmo-trmnl.harnash.com/dashboard
```

#### polling verb
```
GET
```

#### polling headers
```
accept=application/json&authorization=Bearer YOUR_API_TOKEN
```

#### remove bleed margin
```
Yes
```

### sample layout for netatmo-trmnl

```html
<div class="layout layout--col gap--none" style="height:100%; color:black;">

  <div class="title_bar bg--gray-75 border--h-6 rounded--none" style="color:black;">
    <span class="title" style="color:black;">Netatmo</span>
    <span class="instance" style="color:black;">Last updated: {{ StationReading.Timestamp | default: time_utc | date: "%Y-%m-%d %H:%M:%S" }}</span>
  </div>

  <div style="display:flex; flex-direction:column; flex:1 1 auto; min-height:0;">
    <div class="grid grid--cols-2 gap--none"
         style="flex:1 1 auto; min-height:0; grid-template-rows: 1fr 1fr; grid-auto-rows: minmax(0,1fr);">

      <div class="item {% if co2_ppm > 1100 %}bg--gray-60{% endif %} border--h-4 border--v-4"
           style="display:flex; flex-direction:column; justify-content:center; align-items:center;">
        <span class="value value--tnums value--xxxlarge" data-value-fit="true">{{ StationReading.Temperature }}</span>
        <span class="label">°C Temp. w {{ StationReading.Name }}</span>
      </div>

      <div class="item border--h-4 border--v-4"
           style="display:flex; flex-direction:column; justify-content:center; align-items:center;">
        <span class="value value--tnums value--xxxlarge" data-value-fit="true">{{ ModuleReadings[0].Temperature }}</span>
        <span class="label">°C Temp. w {{ ModuleReadings[0].Name }}</span>
      </div>

      <div class="item border--h-4 border--v-4"
           style="display:flex; flex-direction:column; justify-content:center; align-items:center;">
        <span class="value value--tnums value--xxxlarge" data-value-fit="true">{{ StationReading.Humidity }}</span>
        <span class="label">% Wilgotność w {{ StationReading.Name }}</span>
      </div>

      <div class="item border--h-4 border--v-4"
           style="display:flex; flex-direction:column; justify-content:center; align-items:center;">
        <span class="value value--tnums value--xxxlarge" data-value-fit="true">{{ ModuleReadings[0].Humidity }}</span>
        <span class="label">% Wilgotność w {{ ModuleReadings[0].Name }}</span>
      </div>
    </div>
  </div>
</div>
```