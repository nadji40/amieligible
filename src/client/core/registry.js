export class Registry {
  constructor() {
    this._items = new Map();
  }
  register(plugin) {
    if (!plugin || !plugin.name) throw new Error('plugin must have a name');
    if (this._items.has(plugin.name)) {
      throw new Error(`duplicate plugin: ${plugin.name}`);
    }
    this._items.set(plugin.name, plugin);
    return this;
  }
  unregister(name) {
    this._items.delete(name);
    return this;
  }

  get(name) {
    return this._items.get(name);
  }
  has(name) {
    return this._items.has(name);
  }
  list() {
    return [...this._items.values()];
  }
}
