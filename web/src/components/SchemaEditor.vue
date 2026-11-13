<script setup lang="ts">
import NumberInput from "./NumberInput.vue";
import { computed, nextTick, reactive, ref, watch } from "vue";
import type { FormInstance, FormRules } from "element-plus";
import { type Field, type Values } from "../lib/schema";
import { idText, parseJSON, stringify, type Row } from "../lib/json";
import { opts } from "../lib/labels";
import ValidityControl from "./ValidityControl.vue";
import { validityPayload } from "../lib/validity";
import UserSelect from "./UserSelect.vue";
import ResourceSelect from "./ResourceSelect.vue";
const props = defineProps<{
  fields: Field[];
  initial?: Row;
  editing?: boolean;
  busy?: boolean;
  submitLabel?: string;
}>();
const emit = defineEmits<{ save: [data: Row]; cancel: [] }>();
const form = ref<FormInstance>(),
  values = reactive<Values>({}),
  localError = ref(""),
  localErrorField = ref("");
const advancedOpen = ref(false);
let resetting = false;
const visible = computed(() =>
  props.fields.filter((f) => !f.visible || f.visible(values)),
);
function update(key: string, value: unknown) {
  values[key] = Array.isArray(value)
    ? value.map(String)
    : typeof value === "number" || typeof value === "boolean"
      ? value
      : value === null || value === undefined
        ? ""
        : String(value);
}
function selectValue(key: string, multi: boolean): string | string[] {
  return multi
    ? Array.isArray(values[key])
      ? (values[key] as string[])
      : []
    : String(values[key] ?? "");
}
function reset() {
  resetting = true;
  for (const k of Object.keys(values)) delete values[k];
  for (const f of props.fields) {
    const v = props.initial?.[f.key] ?? f.default;
    if (f.type === "json")
      values[f.key] = typeof v === "string" ? v : stringify(v ?? {}, 2);
    else if (f.type === "lines")
      values[f.key] = Array.isArray(v)
        ? v.map(String).join("\n")
        : String(v ?? "");
    else if (["resource", "user"].includes(f.type || ""))
      values[f.key] = idText(v);
    else
      update(
        f.key,
        v ??
          (f.type === "switch"
            ? false
            : f.type === "number"
              ? f.nullable
                ? ""
                : (f.min ?? 0)
              : f.type === "methods" || f.type === "multi"
                ? []
                : ""),
      );
  }
  localError.value = "";
  localErrorField.value = "";
  advancedOpen.value = false;
  void nextTick(() => {
    form.value?.clearValidate();
    resetting = false;
  });
}
watch(() => [props.fields, props.initial], reset, { immediate: true });
// UserSelect includes a nested select and an inline create form. Its change
// event does not reliably reach Element Plus's parent FormItem, so validate
// this field explicitly after the selected value has propagated.
watch(
  () => values.user_id,
  async () => {
    if (resetting || !props.fields.some((f) => f.key === "user_id")) return;
    await nextTick();
    try {
      await form.value?.validateField("user_id");
      form.value?.clearValidate("user_id");
      if (localErrorField.value === "user_id") {
        localError.value = "";
        localErrorField.value = "";
      }
    } catch {
      /* Keep the current field error until the value is valid. */
    }
  },
);
watch(
  () => values.validity_rule,
  (rule) => {
    if (
      !resetting &&
      ["fixed_days", "after_activation"].includes(String(rule)) &&
      Number(values.duration_days) < 1
    )
      values.duration_days = 30;
  },
);
const rules = computed<FormRules>(() =>
  Object.fromEntries(
    visible.value.map((f) => [
      f.key,
      [
        {
          validator: (
            _rule: unknown,
            v: unknown,
            cb: (error?: Error) => void,
          ) => {
            if (f.type === "validity") {
              try {
                validityPayload(values);
              } catch (e) {
                return cb(e as Error);
              }
            }
            if (
              (typeof f.required === "function"
                ? f.required(values)
                : f.required) &&
              (!props.editing || !f.immutable) &&
              (v === "" ||
                v === undefined ||
                (Array.isArray(v) && v.length === 0))
            )
              return cb(new Error(`请填写${f.label}`));
            if (
              typeof v === "string" &&
              f.max &&
              new TextEncoder().encode(v).length > f.max
            )
              return cb(new Error(`${f.label}不能超过 ${f.max} 字节`));
            if (
              f.type === "number" &&
              !(f.nullable && (v === "" || v == null)) &&
              (typeof v !== "number" ||
                !Number.isInteger(v) ||
                v < (f.min ?? 0) ||
                v > (f.max ?? 1000000))
            )
              return cb(new Error("请输入范围内的整数"));
            if (f.type === "json") {
              try {
                const value = parseJSON(String(v));
                if (!value || typeof value !== "object" || Array.isArray(value))
                  return cb(new Error("请输入JSON对象"));
              } catch {
                return cb(new Error("JSON格式不正确"));
              }
            }
            if (
              f.key === "portal_password" &&
              v &&
              new TextEncoder().encode(String(v)).length < 8
            )
              return cb(new Error("密码至少8字节"));
            cb();
          },
          trigger: "blur",
        },
      ],
    ]),
  ),
);
async function submit() {
  localError.value = "";
  localErrorField.value = "";
  // Validate collapsed controls too, independently of DOM visibility. Element
  // Plus may omit hidden controls from its field validation lifecycle.
  for (const f of visible.value) {
    const entries = rules.value[f.key] as {
      validator: (
        rule: unknown,
        value: unknown,
        cb: (error?: Error) => void,
      ) => void;
    }[];
    let message = "";
    entries[0]?.validator(null, values[f.key], (error) => {
      message = error?.message || "";
    });
    if (message) {
      if (f.advanced) advancedOpen.value = true;
      await nextTick();
      await form.value?.validateField(f.key).catch(() => undefined);
      form.value?.scrollToField(f.key);
      (form.value?.$el as HTMLElement | undefined)
        ?.querySelector<HTMLElement>(
          `[data-field="${f.key}"] input, [data-field="${f.key}"] textarea`,
        )
        ?.focus();
      localError.value = message;
      localErrorField.value = f.key;
      return;
    }
  }
  try {
    if (!(await form.value?.validate())) return;
  } catch (errors) {
    const key = Object.keys((errors || {}) as object)[0];
    if (visible.value.some((f) => f.key === key && f.advanced))
      advancedOpen.value = true;
    await nextTick();
    if (key) {
      form.value?.scrollToField(key);
      document
        .querySelector<HTMLElement>(
          `[data-field="${key}"] input, [data-field="${key}"] textarea`,
        )
        ?.focus();
    }
    localError.value = "请检查标注的字段";
    localErrorField.value = key || "";
    return;
  }
  const body: Row = {};
  try {
    for (const f of visible.value) {
      const v = values[f.key];
      if ((props.editing && f.immutable) || (f.type === "password" && !v))
        continue;
      if (f.type === "validity") {
        Object.assign(body, validityPayload(values));
        continue;
      }
      if (["resource", "user"].includes(f.type || "")) {
        if (v) body[f.key] = parseJSON(String(v));
        continue;
      }
      if (f.type === "json") body[f.key] = parseJSON(String(v));
      else if (f.type === "lines")
        body[f.key] = String(v ?? "")
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean);
      else if (f.type === "date") {
        if (v) body[f.key] = new Date(String(v)).toISOString();
        else if (f.nullable) body[f.key] = null;
      } else if (f.type === "number" && f.nullable && (v === "" || v == null))
        body[f.key] = null;
      else body[f.key] = v;
    }

    emit("save", body);
  } catch (e) {
    localError.value = e instanceof Error ? e.message : "字段格式不正确";
  }
}
const methods = opts(["KEY", "FLOATING"]);
const basicMethods = methods.filter((m) =>
  ["KEY", "FLOATING"].includes(m.value),
);
const extraMethods = methods.filter(
  (m) => !["KEY", "FLOATING"].includes(m.value),
);
// Public reset/submit for drawer consumers and integration tests.
defineExpose({ reset, submit, values, advancedOpen });
</script>
<template>
  <el-form
    ref="form"
    :model="values"
    :rules="rules"
    :disabled="busy"
    label-position="top"
    class="schema-form"
    @submit.prevent="submit"
  >
    <el-alert
      v-if="localError"
      :title="localError"
      type="error"
      show-icon
      :closable="false"
    />
    <template v-for="advanced in [false, true]" :key="String(advanced)">
      <el-button
        v-if="advanced && visible.some((f) => f.advanced)"
        class="wide-field"
        :aria-expanded="advancedOpen"
        @click="advancedOpen = !advancedOpen"
      >
        {{ advancedOpen ? "收起更多选项" : "更多选项" }}
      </el-button>
      <div v-show="!advanced || advancedOpen" style="display: contents">
        <template
          v-for="f in visible.filter((f) => !!f.advanced === advanced)"
          :key="f.key"
        >
          <el-form-item
            v-show="!f.hideControl"
            :label="f.label"
            :prop="f.key"
            :error="localErrorField === f.key ? localError : ''"
            :data-field="f.key"
            :class="{
              'wide-field': [
                'textarea',
                'json',
                'lines',
                'methods',
                'multi',
              ].includes(f.type || ''),
            }"
          >
            <template #label>
              {{ f.label
              }}<span
                v-if="
                  typeof f.required === 'function'
                    ? f.required(values)
                    : f.required
                "
                class="required-text"
              >必填</span>
            </template>
            <validity-control
              v-if="f.type === 'validity'"
              :rule="String(values.validity_rule)"
              :days="Number(values.duration_days)"
              :expiry="String(values.expires_at || '')"
              @update:rule="update('validity_rule', $event)"
              @update:days="update('duration_days', $event)"
              @update:expiry="update('expires_at', $event)"
            />
            <user-select
              v-else-if="f.type === 'user'"
              :model-value="String(values[f.key] || '')"
              @update:model-value="update(f.key, $event)"
            />
            <resource-select
              v-else-if="f.type === 'resource'"
              :model-value="String(values[f.key] || '')"
              :endpoint="f.resource!"
              :disabled="editing && f.immutable"
              @update:model-value="update(f.key, $event)"
            />
            <number-input
              v-else-if="f.type === 'number'"
              :model-value="
                values[f.key] === '' ? undefined : Number(values[f.key])
              "
              :min="f.min ?? 0"
              :max="f.max ?? 1000000"
              :precision="0"
              controls-position="right"
              @update:model-value="update(f.key, $event)"
            />
            <el-switch
              v-else-if="f.type === 'switch'"
              :model-value="Boolean(values[f.key])"
              @update:model-value="update(f.key, $event)"
            />
            <el-select
              v-else-if="f.type === 'select' || f.type === 'multi'"
              :model-value="selectValue(f.key, f.type === 'multi')"
              :multiple="f.type === 'multi'"
              @update:model-value="update(f.key, $event)"
            >
              <el-option
                v-for="o in f.options"
                :key="o.value"
                :value="o.value"
                :label="o.label"
              />
            </el-select>
            <div v-else-if="f.type === 'methods'" class="verification-methods">
              <el-checkbox-group
                :model-value="values[f.key] as string[]"
                @update:model-value="update(f.key, $event)"
              >
                <el-checkbox
                  v-for="m in basicMethods"
                  :key="m.value"
                  :value="m.value"
                  :disabled="m.value === 'KEY'"
                >
                  {{ m.label }}
                </el-checkbox>
              </el-checkbox-group>
              <details v-if="extraMethods.length" class="verification-options">
                <summary>更多选项</summary>
                <el-checkbox-group
                  :model-value="values[f.key] as string[]"
                  @update:model-value="update(f.key, $event)"
                >
                  <el-checkbox
                    v-for="m in extraMethods"
                    :key="m.value"
                    :value="m.value"
                  >
                    {{ m.label }}
                  </el-checkbox>
                </el-checkbox-group>
              </details>
            </div>
            <el-date-picker
              v-else-if="f.type === 'date'"
              :model-value="String(values[f.key] || '')"
              type="datetime"
              value-format="YYYY-MM-DDTHH:mm:ssZ"
              placeholder="选择日期和时间"
              @update:model-value="update(f.key, $event)"
            />
            <el-input
              v-else
              :model-value="String(values[f.key] ?? '')"
              :type="
                ['textarea', 'json', 'lines'].includes(f.type || '')
                  ? 'textarea'
                  : f.type === 'password'
                    ? 'password'
                    : 'text'
              "
              :show-password="f.type === 'password'"
              :rows="f.type === 'json' ? 5 : 3"
              :autocomplete="f.type === 'password' ? 'new-password' : 'off'"
              @update:model-value="update(f.key, $event)"
            />
            <p v-if="f.hint" class="field-hint">
              {{ f.hint }}
            </p>
          </el-form-item>
          <slot name="after-field" :field="f" :values="values" />
        </template>
      </div>
    </template>
    <div class="form-footer wide-field">
      <el-button @click="emit('cancel')">
        取消
      </el-button><el-button type="primary" native-type="submit" :loading="busy">
        {{ submitLabel || "保存设置" }}
      </el-button>
    </div>
  </el-form>
</template>
